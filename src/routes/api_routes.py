from flask import Blueprint, request, jsonify
from src.extensions import db # Import db from extensions
from src.modules.models import Receipt
from sqlalchemy import text
from src.modules.models import Issuer
from src.modules.models import EndpointUrl
from src.auth.jwt_auth import token_required
from cryptography.fernet import Fernet
import os
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime

import boto3
from botocore.exceptions import BotoCoreError, NoCredentialsError
import tempfile

fernet = Fernet(os.getenv("FERNET_KEY"))

# Define the blueprint
api_bp = Blueprint(
    'api_bp', __name__
)

@api_bp.route('/issue-receipt', methods=['POST'])
@token_required
def issue_receipt():
    issuer_code = request.issuer_code  # extracted from token

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    req = data.get("req")

    if not req:
        return jsonify({"error": "Missing 'req' field in request body."}), 400

    action      = req.get("action")
    receipt_id  = req.get("receipt_id")
    issuer_code = req.get("issuer_code")
    payer       = req.get("payer")
    amount      = req.get("amount")
    date        = req.get("date")
    description = req.get("description")

    if not action:
        return jsonify({"error": "The 'action' field is required."}), 400
    if not issuer_code:
        return jsonify({"error": "The 'issuer_code' field is required."}), 400

    issuer = Issuer.query.filter_by(issuer_code=issuer_code).first()
    if not issuer:
        return jsonify({"error": f"Issuer '{issuer_code}' is not registered."}), 404

    if not issuer.active:
        return jsonify({"error": "Issuer is deactivated. Cannot issue receipts."}), 403

    if issuer.certificate_expires_at and issuer.certificate_expires_at < datetime.utcnow():
        vencimento = issuer.certificate_expires_at.strftime("%d/%m/%Y %H:%M")
        return jsonify({"error": f"Certificate expired on {vencimento}. Please update it to continue."}), 403

    required_map = {
        "issue":   ["action", "receipt_id", "issuer_code", "payer", "amount", "date", "description"],
        "cancel":  ["action", "receipt_id", "issuer_code", "description"],
        "consult": ["action", "receipt_id", "issuer_code"]
    }

    required = required_map.get(action)
    if required is None:
        return jsonify({
            "error": f"Unsupported action '{action}'. Use 'issue', 'cancel' or 'consult'."
        }), 400

    missing = [field for field in required if field not in req]
    if missing:
        return jsonify({
            "error": f"Missing required fields: {', '.join(missing)}"
        }), 400

    receipt = Receipt()
    try:
        receipt.load_from_dict(req)
        db.session.add(receipt)
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

    receipt_key = "309C63F3-5F7D-4007-BD3B-53E3690E32B6"
    if action == "issue":
        message = "Issue request registered successfully"
    elif action == "cancel":
        message = "Cancel request registered successfully"
    elif action == "consult":
        message = "Consultation completed successfully"
    else:
        return jsonify({"error": "Invalid action."}), 400

    return jsonify({
        "data": {
            "receipt_id": str(req["receipt_id"]),
            "issuer_code": issuer_code,
            "success": True,
            "message": message,
        }
    }), 200

@api_bp.route('/endpoint', methods=['POST'])
@token_required
def registrar_endpoint():
    issuer_code = request.issuer_code
    if not request.is_json:
        return jsonify({"error": "O corpo da requisição deve estar em formato JSON."}), 400

    data = request.get_json()
    url = data.get("url")
    token_endpoint = data.get("token")

    if not url or not token_endpoint:
        return jsonify({"error": "Campos 'url' e 'token' são obrigatórios."}), 400

    ip_remoto = request.headers.get('X-Forwarded-For', request.remote_addr)

    novo_callback = EndpointUrl(
        issuer_code=issuer_code,
        url=url,
        token=token_endpoint,
        ip=ip_remoto
    )

    try:
        db.session.add(novo_callback)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Erro ao registrar callback.", "detalhes": str(e)}), 500

    return jsonify({
        "message": "Callback registrado com sucesso.",
        "callback_id": novo_callback.id
    }), 200


@api_bp.route('/issuers', methods=['POST'])
@token_required
def register_issuer():
    """
    Ativa (cria ou atualiza) ou desativa um issuer com base no campo 'action'.
    A senha do certificado é criptografada com Fernet e validada.
    """
    issuer_code = request.issuer_code

    issuer_data = {}
    file = None
    is_multipart = 'multipart/form-data' in request.content_type if request.content_type else False

    if is_multipart:
        issuer_data = {
            "action": request.form.get("action"),
            "issuer_code": request.form.get("issuer_code"),
            "cpf": request.form.get("cpf"),
            "password": request.form.get("password"),
        }
        file = request.files.get("certificate")
    elif request.is_json:
        data = request.get_json()
        issuer_data = data.get("req")
        if not issuer_data:
            return jsonify({"error_code": "ISSUERS_ERROR_001", "error_message": "Missing 'req' field"}), 400
    else:
        return jsonify({"error_code": "ISSUERS_ERROR_002", "error_message": "Content-Type deve ser multipart/form-data ou application/json."}), 400

    action = issuer_data.get("action")
    if action not in {"enable", "disable"}:
        return jsonify({"error_code": "ISSUERS_ERROR_003", "error_message": "Invalid 'action'. Use 'enable' or 'disable'."}), 400

    issuer_code_in_req = issuer_data.get("issuer_code")
    if not issuer_code_in_req:
        return jsonify({"error_code": "ISSUERS_ERROR_004", "error_message": "Missing field: issuer_code"}), 400

    issuer = Issuer.query.filter_by(issuer_code=issuer_code_in_req).first()

    if action == "enable":
        if not issuer and not file:
            return jsonify({"error_code": "ISSUERS_ERROR_005", "error_message": "Certificate file (.pfx) is required for new issuer."}), 400
        if not issuer and not issuer_data.get("cpf"):
            return jsonify({"error_code": "ISSUERS_ERROR_006", "error_message": "Missing field: cpf"}), 400
        if not issuer and not issuer_data.get("password"):
            return jsonify({"error_code": "ISSUERS_ERROR_007", "error_message": "Missing field: password"}), 400

        if file:
            pfx_bytes = file.read()
            try:
                senha_cert = issuer_data["password"]
                private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, senha_cert.encode())

                if cert is None:
                    return jsonify({"error_code": "ISSUERS_ERROR_008", "error_message": "Invalid or missing certificate in the PFX file."}), 400

                now = datetime.utcnow()
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after

                if now < not_before:
                    return jsonify({"error_code": "ISSUERS_ERROR_009", "error_message": f"Certificate is not yet valid. Start date: {not_before}"}), 400
                if now > not_after:
                    return jsonify({"error_code": "ISSUERS_ERROR_010", "error_message": f"Certificate expired on: {not_after}"}), 400

                fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()

            except ValueError as e:
                return jsonify({"error_code": "ISSUERS_ERROR_011", "error_message": f"Error processing certificate: {e}"}), 400
            except Exception as e:
                return jsonify({"error_code": "ISSUERS_ERROR_012", "error_message": f"Unexpected error: {e}"}), 500

            def upload_certificado_s3(fingerprint: str, pfx_bytes: bytes):
                s3 = boto3.client(
                    's3',
                    aws_access_key_id=os.getenv('AWS_ACCESS_KEY'),
                    aws_secret_access_key=os.getenv('AWS_SECRET_KEY'),
                    region_name='sa-east-1'
                )

                bucket = 'rs-easy'
                key_name = f'cert/{fingerprint}.rbt'

                try:
                    temp_path = os.path.join(tempfile.gettempdir(), f"{fingerprint}.pfx")
                    with open(temp_path, 'wb') as f:
                        f.write(pfx_bytes)

                    s3.upload_file(temp_path, bucket, key_name)
                    os.remove(temp_path)
                    return True, None

                except (BotoCoreError, NoCredentialsError, Exception) as e:
                    return False, str(e)

            ok, err = upload_certificado_s3(fingerprint, pfx_bytes)
            if not ok:
                return jsonify({"error_code": "ISSUERS_ERROR_013", "error_message": f"Error uploading certificate to S3: {err}"}), 500

            encrypted_password = fernet.encrypt(senha_cert.encode()).decode()

            if issuer:
                if "issuer_code" in issuer_data and issuer_data["issuer_code"] != issuer.issuer_code:
                    return jsonify({"error_code": "ISSUERS_ERROR_014", "error_message": "'issuer_code' cannot be changed."}), 400
                if "cpf" in issuer_data and issuer_data["cpf"] != issuer.cpf:
                    return jsonify({"error_code": "ISSUERS_ERROR_015", "error_message": "'cpf' cannot be changed."}), 400
                if "id" in issuer_data and str(issuer_data["id"]) != str(issuer.id):
                    return jsonify({"error_code": "ISSUERS_ERROR_016", "error_message": "'id' cannot be changed."}), 400

                issuer.certificate = fingerprint
                issuer.password = encrypted_password
                issuer.certificate_expires_at = not_after
                issuer.active = True
                message = "Issuer updated and enabled successfully."
            else:
                new_issuer = Issuer(
                    issuer_code=issuer_code_in_req,
                    cpf=issuer_data["cpf"],
                    certificate=fingerprint,
                    password=encrypted_password,
                    certificate_expires_at=not_after,
                    active=True
                )
                db.session.add(new_issuer)
                issuer = new_issuer
                message = "Issuer created and enabled successfully."

        elif issuer:
            issuer.active = True
            message = "Issuer reactivated successfully."

        try:
            db.session.commit()
            return jsonify({
                "data": {
                    "id": issuer.id,
                    "issuer_code": issuer.issuer_code
                },
                "message": message
            }), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error_code": "ISSUERS_ERROR_017", "error_message": "DB error: " + str(e)}), 500

    elif action == "disable":
        if not issuer:
            return jsonify({"error_code": "ISSUERS_ERROR_018", "error_message": "Issuer not found for disable"}), 404

        issuer.active = False
        try:
            db.session.commit()
            return jsonify({
                "data": {
                    "id": issuer.id,
                    "issuer_code": issuer.issuer_code
                },
                "message": "Issuer disabled successfully."
            }), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error_code": "ISSUERS_ERROR_019", "error_message": "DB error: " + str(e)}), 500

@api_bp.route("/test-db")
def test_db():
    try:
        result = db.session.execute(text("SELECT 1"))
        return "Conexão com MySQL ok!"
    except Exception as e:
        return f"Erro ao conectar: {str(e)}"
 
"""
@api_bp.route('/emitentes/login-decrypt', methods=['POST'])
def login_emitente_decrypt():

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    client_code = data.get("client_code")
    if not client_code:
        return jsonify({"error": "Field 'client_code' is required."}), 400

    emitente = Emitente.query.filter_by(client_code=client_code).first()
    if not emitente:
        return jsonify({"error": "Emitente não encontrado."}), 404

    try:
        decrypted = fernet.decrypt(emitente.senha.encode()).decode()
    except Exception:
        return jsonify({"error": "Falha ao descriptografar senha."}), 500

    return jsonify({
        "client_code": client_code,
        "senha_decrypted": decrypted
    }), 200
"""    