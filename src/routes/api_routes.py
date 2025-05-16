from flask import Blueprint, request, jsonify
from src.auth.admin_jwt_auth import admin_token_required
from src.extensions import db # Import db from extensions
from src.modules.models import Receipt
from sqlalchemy import or_, text
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

@api_bp.route('/receipts', methods=['POST'])
@token_required
def issue_receipt():
    issuer_code = request.issuer_code  # Extraído do token

    if not request.is_json:
        return jsonify({
            "error_code": "RECEIPT_ERROR_001",
            "error_message": "Request must be JSON"
        }), 400

    data = request.get_json()
    req = data.get("req")

    if not req:
        return jsonify({
            "error_code": "RECEIPT_ERROR_002",
            "error_message": "Missing 'req' field in request body."
        }), 400

    action      = req.get("action")
    receipt_id  = req.get("receipt_id")
    issuer_code = req.get("issuer_code")
    payer       = req.get("payer")
    amount      = req.get("amount")
    date        = req.get("date")
    description = req.get("description")
    reason      = req.get("reason")
    test_flag   = req.get("test", False)

    if not action:
        return jsonify({
            "error_code": "RECEIPT_ERROR_003",
            "error_message": "The 'action' field is required."
        }), 400

    if not issuer_code:
        return jsonify({
            "error_code": "RECEIPT_ERROR_004",
            "error_message": "Missing field: issuer_code"
        }), 400

    issuer = Issuer.query.filter_by(issuer_code=issuer_code).first()
    if not issuer:
        return jsonify({
            "error_code": "ISSUER_ERROR_001",
            "error_message": f"Issuer '{issuer_code}' is not registered."
        }), 404

    if not issuer.active:
        return jsonify({
            "error_code": "ISSUER_ERROR_002",
            "error_message": "Issuer is deactivated. Cannot issue receipts."
        }), 403

    if issuer.certificate_expires_at and issuer.certificate_expires_at < datetime.utcnow():
        vencimento = issuer.certificate_expires_at.strftime("%d/%m/%Y %H:%M")
        return jsonify({
            "error_code": "ISSUER_ERROR_003",
            "error_message": f"Certificate expired on {vencimento}. Please update it to continue."
        }), 403

    required_map = {
        "issue":   ["action", "receipt_id", "issuer_code", "payer", "amount", "date", "description"],
        "cancel":  ["action", "receipt_id", "issuer_code", "description"]
    }

    required = required_map.get(action)
    if required is None:
        return jsonify({
            "error_code": "RECEIPT_ERROR_005",
            "error_message": f"Unsupported action '{action}'. Use 'issue' or 'cancel'."
        }), 400

    missing = [field for field in required if field not in req]
    if missing:
        return jsonify({
            "error_code": "RECEIPT_ERROR_006",
            "error_message": f"Missing required fields: {', '.join(missing)}"
        }), 400

    if action == "issue" and description is None:
        return jsonify({
            "error_code": "RECEIPT_ERROR_007",
            "error_message": "'description' field must be present (can be empty string)"
        }), 400

    if reason is not None and action != "cancel":
        return jsonify({
            "error_code": "RECEIPT_ERROR_008",
            "error_message": "Field 'reason' is only allowed when action is 'cancel'"
        }), 400

    existing = Receipt.query.filter_by(
        receipt_id=receipt_id,
        issuer_code=issuer_code,
        test=bool(test_flag)
    ).first()

    if action == "cancel":
        if not existing:
            return jsonify({
                "error_code": "RECEIPT_ERROR_009",
                "error_message": "Cannot cancel: receipt not found with provided receipt_id and issuer_code."
            }), 404

        existing.Status = 90
        existing.reason = reason
        existing.description = description or ""
        db.session.commit()

        return jsonify({
            "data": {
                "receipt_id": str(receipt_id),
                "issuer_code": issuer_code,
                "success": True,
                "message": "Cancel request registered successfully"
            }
        }), 200

    if existing:
        return jsonify({
            "error_code": "RECEIPT_ERROR_010",
            "error_message": "A receipt with this receipt_id and issuer_code already exists."
        }), 409

    receipt = Receipt()
    try:
        receipt.load_from_dict(req)
        receipt.test = bool(test_flag)
        db.session.add(receipt)
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify({
            "error_code": "RECEIPT_ERROR_011",
            "error_message": str(e)
        }), 400

    message = {
        "issue": "Issue request registered successfully",
        "cancel": "Cancel request registered successfully"
    }.get(action, "Request completed")

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
        return jsonify({
            "error_code": "ENDPOINT_ERROR_001",
            "error_message": "O corpo da requisição deve estar em formato JSON."
        }), 400

    data = request.get_json()
    url = data.get("url")
    token_endpoint = data.get("token")

    if not url or not token_endpoint:
        return jsonify({
            "error_code": "ENDPOINT_ERROR_002",
            "error_message": "Campos 'url' e 'token' são obrigatórios."
        }), 400

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
        return jsonify({
            "error_code": "ENDPOINT_ERROR_003",
            "error_message": "Erro ao registrar callback.",
            "details": str(e)
        }), 500

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
                issuer.disable_date = None  # <-- limpa se estava desabilitado
                message = "Issuer updated and enabled successfully."
            else:
                new_issuer = Issuer(
                    issuer_code=issuer_code_in_req,
                    cpf=issuer_data["cpf"],
                    certificate=fingerprint,
                    password=encrypted_password,
                    certificate_expires_at=not_after,
                    active=True,
                    enable_date=datetime.utcnow()  # <-- define apenas na criação
                )
                db.session.add(new_issuer)
                issuer = new_issuer
                message = "Issuer created and enabled successfully."

        elif issuer:
            issuer.active = True
            issuer.disable_date = None  # <-- limpa disable_date
            message = "Issuer reactivated successfully."

        try:
            db.session.commit()
            return jsonify({
                "data": {
                    "id": issuer.id,
                    "issuer_code": issuer.issuer_code,
                    "expires_at": issuer.certificate_expires_at.isoformat() if issuer.certificate_expires_at else None
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
        issuer.disable_date = datetime.utcnow()  # <-- registra a desativação
        try:
            db.session.commit()
            return jsonify({
                "data": {
                    "id": issuer.id,
                    "issuer_code": issuer.issuer_code,
                },
                "message": "Issuer disabled successfully."
            }), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error_code": "ISSUERS_ERROR_019", "error_message": "DB error: " + str(e)}), 500

@api_bp.route('/task', methods=['POST'])
@admin_token_required
def get_pending_task():
    try:
        data = request.get_json(silent=True) or {}
        preferred_cpf = data.get("preferred")

        receipt = None
        issuer = None

        if preferred_cpf:
            issuer = Issuer.query.filter_by(cpf=preferred_cpf).first()

            if issuer:
                issuer_code_str = str(issuer.issuer_code)
                receipt = (
                    Receipt.query
                    .filter(
                        Receipt.issuer_code == issuer_code_str,
                        Receipt.Status.in_(["0", "90"])
                    )
                    .order_by(Receipt.received_at.asc())
                    .first()
                )
        else:
            receipt = (
                Receipt.query
                .filter(Receipt.Status.in_(["0", "90"]))
                .order_by(Receipt.received_at.asc())
                .first()
            )

        if not receipt:
            return jsonify({
                "error_code": "TASK_ERROR_001",
                "error_message": "No pending tasks found."
            }), 204

        if not issuer:
            issuer = Issuer.query.filter_by(issuer_code=str(receipt.issuer_code)).first()

        decrypted_password = None
        if issuer and issuer.password:
            try:
                decrypted_password = fernet.decrypt(issuer.password.encode()).decode()
            except Exception:
                return jsonify({
                    "error_code": "TASK_ERROR_002",
                    "error_message": "Failed to decrypt issuer password"
                }), 500

        result = {
            "id": receipt.idRS,
            "issuer_code": receipt.issuer_code,
            "issuer_cpf": issuer.cpf if issuer else None,
            "certificate": issuer.certificate if issuer else None,
            "password": decrypted_password,
            "receipt_id": receipt.receipt_id,
            "payer": receipt.payer,
            "beneficiary": receipt.beneficiary,
            "amount": str(receipt.amount),
            "date": receipt.date.isoformat() if receipt.date else None,
            "description": receipt.description,
            "test": receipt.test,
            "status": receipt.Status,
            "received_at": receipt.received_at.isoformat() if receipt.received_at else None,
        }

        if receipt.Numero is not None:
            result["receipt_number"] = receipt.Numero

        if hasattr(receipt, "reason") and receipt.reason is not None:
            result["reason"] = receipt.reason

        return jsonify(result), 200

    except Exception as e:
        return jsonify({
            "error_code": "TASK_ERROR_999",
            "error_message": "Unexpected error.",
            "details": str(e)
        }), 500
    
@api_bp.route('/task-return', methods=['POST'])
@admin_token_required
def update_task_return():
    try:
        data = request.get_json()

        issuer_code = data.get("issuer_code")
        receipt_id = data.get("receipt_id")

        if issuer_code is None or receipt_id is None:
            return jsonify({
                "error_code": "TASK_RETURN_ERROR_001",
                "error_message": "issuer_code and receipt_id are required."
            }), 400

        # Busca o receipt com os dados fornecidos
        receipt = Receipt.query.filter_by(
            issuer_code=str(issuer_code),
            receipt_id=receipt_id
        ).first()

        if not receipt:
            return jsonify({
                "error_code": "TASK_RETURN_ERROR_002",
                "error_message": "No receipt found for given issuer_code and receipt_id."
            }), 404

        # Campos opcionais a atualizar
        if "status" in data:
            receipt.Status = data["status"]

        if "process_date" in data:
            try:
                receipt.DataRS = datetime.fromisoformat(data["process_date"])
            except Exception:
                return jsonify({
                    "error_code": "TASK_RETURN_ERROR_003",
                    "error_message": "Invalid format for process_date. Use ISO 8601."
                }), 400

        if "key" in data:
            receipt.Chave = data["key"]

        if "receipt_number" in data:
            receipt.Numero = data["receipt_number"]

        db.session.commit()

        return jsonify({
            "message": "Receipt updated successfully."
        }), 200

    except Exception as e:
        return jsonify({
            "error_code": "TASK_RETURN_ERROR_999",
            "error_message": "Unexpected error.",
            "details": str(e)
        }), 500
    
@api_bp.route('/query', methods=['POST'])
@token_required
def query_receipt_status():
    try:
        data = request.get_json()
        issuer_code = data.get("issuer_code")
        receipt_id = data.get("receipt_id")

        if not issuer_code or not receipt_id:
            return jsonify({
                "error_code": "QUERY_ERROR_001",
                "error_message": "Both issuer_code and receipt_id are required."
            }), 400

        receipt = Receipt.query.filter_by(
            issuer_code=str(issuer_code),
            receipt_id=receipt_id
        ).first()

        if not receipt:
            return jsonify({
                "error_code": "QUERY_ERROR_002",
                "error_message": "Receipt not found with provided issuer_code and receipt_id."
            }), 404

        # Define mapeamento de status → descrição
        status_map = {
            "0": "queued",
            "10": "issued",
            "90": "cancellation queue",
            "99": "canceled",
            0: "queued",
            10: "issued",
            90: "cancellation queue",
            99: "canceled"
        }

        status_desc = status_map.get(receipt.Status, "unknown status")

        return jsonify({
            "status_code": receipt.Status,
            "key": receipt.Chave,
            "file": "https://example.com/teste.pdf",  # URL temporária
            "status_description": status_desc
        }), 200

    except Exception as e:
        return jsonify({
            "error_code": "QUERY_ERROR_999",
            "error_message": "Unexpected error.",
            "details": str(e)
        }), 500
 
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