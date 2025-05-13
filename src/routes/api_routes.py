from flask import Blueprint, request, jsonify
from src.extensions import db # Import db from extensions
from src.modules.models import Recibo
from sqlalchemy import text
from src.modules.models import Emitente
from src.modules.models import EndpointUrl
from src.auth.jwt_auth import token_required
from cryptography.fernet import Fernet
import os
from cryptography.hazmat.primitives import hashes



from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
import re



fernet = Fernet(os.getenv("FERNET_KEY"))

# Define the blueprint
api_bp = Blueprint(
    'api_bp', __name__
)

@api_bp.route('/emitir-recibo', methods=['POST'])
@token_required
def issue_receipt():
    """
    Endpoint to receive requests to issue, cancel, or consult receipts.
    The action is defined by the 'action' field inside the 'req' object.
    """
    client_code = request.client_code  # extracted from token
    # print(f"Valid token for client {client_code}")

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    req = data.get("req")

    # print(f"Received data: {req}")

    if not req:
        return jsonify({"error": "Missing 'req' field in request body."}), 400

    action      = req.get("action")
    receipt_id  = req.get("receipt_id")
    client_code = req.get("client_code")
    payer       = req.get("payer")
    amount      = req.get("amount")
    date        = req.get("date")
    description = req.get("description")

    if not action:
        return jsonify({"error": "The 'action' field is required."}), 400
    if not client_code:
        return jsonify({"error": "The 'client_code' field is required."}), 400

    issuer = Emitente.query.filter_by(client_code=client_code).first()
    if not issuer:
        # print(f"[ERROR] Client '{client_code}' not found.")
        return jsonify({"error": f"Client '{client_code}' is not registered."}), 404

    required_map = {
        "issue":   ["action", "receipt_id", "client_code", "payer", "amount", "date", "description"],
        "cancel":  ["action", "receipt_id", "client_code", "description"],
        "consult": ["action", "receipt_id", "client_code"]
    }
    
    required = required_map.get(action)

    if required is None:
        return jsonify({
            "error": f"Unsupported action '{action}'. Use 'issue', 'cancel' or 'consult'."
        }), 400

    # checa quais campos faltam
    missing = [field for field in required if field not in req]
    if missing:
        return jsonify({
            "error": f"Missing required fields: {', '.join(missing)}"
        }), 400
    
    # registra no banco
    receipt = Recibo()
    try:
        receipt.load_from_dict(req)
        db.session.add(receipt)
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

    # Simulated response per action
    receipt_key = "309C63F3-5F7D-4007-BD3B-53E3690E32B6"
    if action == "issue":
        file_url = "https://www.exemplo.com/receipt-issued.pdf"
        message = "Issue request registered successfully"
    elif action == "cancel":
        file_url = "https://www.exemplo.com/receipt-canceled.pdf"
        message = "Cancel request registered successfully"
    elif action == "consult":
        file_url = "https://www.exemplo.com/receipt.pdf"
        message = "Consultation completed successfully"
    else:
        return jsonify({"error": "Invalid action."}), 400

    return jsonify({
        "data": {
            "receipt_id": str(req["receipt_id"]),
            "client_code": client_code,
            "success": True,
            "receipt_key": receipt_key,
            "file_url": file_url,
            "message": message,
        }
    }), 200

@api_bp.route('/endpoint', methods=['POST'])
@token_required
def registrar_endpoint():
    """
    Registra uma URL de endpoint fornecida por um cliente.
    Requer autenticação via token.
    """
    client_code = request.client_code
    if not request.is_json:
        return jsonify({"error": "O corpo da requisição deve estar em formato JSON."}), 400

    data = request.get_json()
    url = data.get("url")
    token_endpoint = data.get("token")  # token que o sistema deve enviar no callback

    if not url or not token_endpoint:
        return jsonify({"error": "Campos 'url' e 'token' são obrigatórios."}), 400

    ip_remoto = request.headers.get('X-Forwarded-For', request.remote_addr)

    novo_callback = EndpointUrl(
        client_code=client_code,
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
    }), 201
    
from flask import request, jsonify
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from datetime import datetime
import re

@api_bp.route('/emitentes', methods=['POST'])
@token_required
def register_emitente():
    """
    Ativa (cria ou atualiza) ou desativa um emitente com base no campo 'action'.
    A senha do certificado é criptografada com Fernet e validada.
    """
    client_code = request.client_code

    # Suporte a multipart/form-data ou JSON puro
    is_multipart = 'multipart/form-data' in request.content_type

    if is_multipart:
        emitente_data = {
            "action": request.form.get("action"),
            "client_code": request.form.get("client_code"),
            "cpf": request.form.get("cpf"),
            "password": request.form.get("password"),
        }
        file = request.files.get("certificate")
        if not file:
            return jsonify({"error": "Arquivo de certificado (.pfx) não enviado."}), 400
        pfx_bytes = file.read()
    else:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        emitente_data = data.get("req")
        if not emitente_data:
            return jsonify({"error": "Missing 'req' field"}), 400
        try:
            pfx_bytes = bytes.fromhex(emitente_data["certificate"])
        except Exception:
            return jsonify({"error": "Campo 'certificate' deve estar em formato hexadecimal."}), 400

    action = emitente_data.get("action")
    if action not in {"enable", "disable"}:
        return jsonify({"error": "Invalid 'action'. Use 'enable' or 'disable'."}), 400

    client_code_in_req = emitente_data.get("client_code")
    if not client_code_in_req:
        return jsonify({"error": "Missing field: client_code"}), 400

    emitente = Emitente.query.filter_by(client_code=client_code_in_req).first()

    if action == "enable":
        for field in ("cpf", "password"):
            if not emitente and not emitente_data.get(field):
                return jsonify({"error": f"Missing field: {field}"}), 400

        # Valida o certificado e obtém vencimento
        try:
            senha_cert = emitente_data["password"]
            private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, senha_cert.encode())

            if cert is None:
                return jsonify({"error": "Certificado inválido ou ausente no PFX."}), 400

            now = datetime.utcnow()
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

            if now < not_before:
                return jsonify({"error": f"Certificado ainda não é válido. Início: {not_before}"}), 400
            if now > not_after:
                return jsonify({"error": f"Certificado expirado em: {not_after}"}), 400

            # Extrai fingerprint (SHA256)
            fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()

        except ValueError as e:
            return jsonify({"error": f"Erro ao processar certificado: {e}"}), 400
        except Exception as e:
            return jsonify({"error": f"Erro inesperado: {e}"}), 500

        # Criptografa senha para armazenamento
        encrypted_password = fernet.encrypt(senha_cert.encode()).decode()

        if emitente:
            if "client_code" in emitente_data and emitente_data["client_code"] != emitente.client_code:
                return jsonify({"error": "'client_code' cannot be changed."}), 400
            if "cpf" in emitente_data and emitente_data["cpf"] != emitente.cpf:
                return jsonify({"error": "'cpf' cannot be changed."}), 400
            if "id" in emitente_data and str(emitente_data["id"]) != str(emitente.id):
                return jsonify({"error": "'id' cannot be changed."}), 400

            emitente.certificate = fingerprint  # Salva fingerprint
            emitente.password = encrypted_password
            emitente.certificate_expires_at = not_after
            emitente.active = True
            message = "Emitente updated and enabled successfully."
        else:
            new_emitente = Emitente(
                client_code=client_code_in_req,
                cpf=emitente_data["cpf"],
                certificate=fingerprint,  # Salva fingerprint
                password=encrypted_password,
                certificate_expires_at=not_after,
                active=True
            )
            db.session.add(new_emitente)
            emitente = new_emitente
            message = "Emitente created and enabled successfully."

        try:
            db.session.commit()
            return jsonify({
                "data": {
                    "id": emitente.id,
                    "client_code": emitente.client_code
                },
                "message": message
            }), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": "DB error: " + str(e)}), 500

    elif action == "disable":
        if not emitente:
            return jsonify({"error": "Emitente not found for disable"}), 404

        emitente.active = False
        try:
            db.session.commit()
            return jsonify({
                "data": {
                    "id": emitente.id,
                    "client_code": emitente.client_code
                },
                "message": "Emitente disabled successfully."
            }), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": "DB error: " + str(e)}), 500


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