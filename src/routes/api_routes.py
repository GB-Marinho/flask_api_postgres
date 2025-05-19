import re
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

def is_valid_cpf(cpf: str) -> bool:
    cpf = re.sub(r"\D", "", cpf)
    if not cpf or len(cpf) != 11 or cpf == cpf[0] * 11:
        return False

    for i in [9, 10]:
        value = sum((int(cpf[num]) * ((i + 1) - num) for num in range(i)))
        digit = ((value * 10) % 11) % 10
        if digit != int(cpf[i]):
            return False
    return True

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
    issuer_code = req.get("issuer_code")
    receipt_id  = req.get("receipt_id")
    payer       = req.get("payer")
    beneficiary = req.get("beneficiary")
    amount      = req.get("amount")
    date        = req.get("date")
    description = req.get("description")
    reason      = req.get("reason")
    test_flag   = req.get("test", False)

    if not isinstance(test_flag, bool):
        return jsonify({
            "error_code": "RECEIPT_ERROR_021",
            "error_message": "Field 'test' must be boolean (true or false)"
        }), 400

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

    # Campos obrigatórios por ação
    required_map = {
        "issue":   ["action", "receipt_id", "payer", "amount", "date", "description"],
        "cancel":  ["action", "receipt_id", "reason"]
    }

    required = required_map.get(action)
    if required is None:
        return jsonify({
            "error_code": "RECEIPT_ERROR_005",
            "error_message": f"Unsupported action '{action}'. Use 'issue' or 'cancel'."
        }), 400

    # ✅ Permite description vazio, mas exige presença
    missing = []
    for field in required:
        if field not in req:
            missing.append(field)
        elif field != "description" and not req.get(field) and req.get(field) != 0:
            missing.append(field)

    if missing:
        return jsonify({
            "error_code": "RECEIPT_ERROR_006",
            "error_message": f"Missing required fields: {', '.join(missing)}"
        }), 400

    if reason is not None and action != "cancel":
        return jsonify({
            "error_code": "RECEIPT_ERROR_008",
            "error_message": "Field 'reason' is only allowed when action is 'cancel'"
        }), 400

    # ⚠️ Validações específicas para ação "issue"
    if action == "issue":
        if not payer:
            return jsonify({
                "error_code": "RECEIPT_ERROR_012",
                "error_message": "Field 'payer' is required."
            }), 400

        if not is_valid_cpf(payer):
            return jsonify({
                "error_code": "RECEIPT_ERROR_013",
                "error_message": f"Invalid CPF for payer: {payer}"
            }), 400

        if payer == issuer.cpf:
            return jsonify({
                "error_code": "RECEIPT_ERROR_014",
                "error_message": "Payer CPF cannot be the same as the issuer CPF."
            }), 400

        if beneficiary:
            if not is_valid_cpf(beneficiary):
                return jsonify({
                    "error_code": "RECEIPT_ERROR_015",
                    "error_message": f"Invalid CPF for beneficiary: {beneficiary}"
                }), 400

        if not isinstance(amount, (int, float)):
            return jsonify({
                "error_code": "RECEIPT_ERROR_016",
                "error_message": "Amount must be a number (not string)."
            }), 400

        if amount > 99999999.99:
            return jsonify({
                "error_code": "RECEIPT_ERROR_017",
                "error_message": "Amount exceeds maximum allowed value of 99,999,999.99"
            }), 400

        if date in (None, ""):
            return jsonify({
                "error_code": "RECEIPT_ERROR_018",
                "error_message": "Field 'date' cannot be null or empty."
            }), 400

        try:
            parsed_date = datetime.fromisoformat(date)
        except ValueError:
            return jsonify({
                "error_code": "RECEIPT_ERROR_019",
                "error_message": "Field 'date' must be a valid ISO 8601 datetime string."
            }), 400

        if parsed_date > datetime.utcnow():
            return jsonify({
                "error_code": "RECEIPT_ERROR_020",
                "error_message": "Field 'date' cannot be a future date."
            }), 400

    # Verifica se já existe
    existing = Receipt.query.filter_by(
        receipt_id=receipt_id,
        issuer_code=issuer_code,
        test=test_flag
    ).first()

    if action == "cancel":
        if not existing:
            return jsonify({
                "error_code": "RECEIPT_ERROR_009",
                "error_message": "Cannot cancel: receipt not found with provided receipt_id and issuer_code."
            }), 404

        if existing.Status in (90, 99):
            return jsonify({
                "error_code": "RECEIPT_ERROR_010",
                "error_message": f"Receipt already cancelled or cancellation in progress (status {existing.Status})."
            }), 400

        if not reason:
            return jsonify({
                "error_code": "RECEIPT_ERROR_011",
                "error_message": "Field 'reason' is required when cancelling a receipt."
            }), 400

        existing.Status = 90
        existing.reason = reason
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
            "error_code": "RECEIPT_ERROR_012",
            "error_message": "A receipt with this receipt_id and issuer_code already exists."
        }), 409

    # Novo registro
    receipt = Receipt()
    try:
        receipt.load_from_dict(req)
        receipt.test = test_flag
        db.session.add(receipt)
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify({
            "error_code": "RECEIPT_ERROR_013",
            "error_message": str(e)
        }), 400

    return jsonify({
        "data": {
            "receipt_id": str(receipt_id),
            "issuer_code": issuer_code,
            "success": True,
            "message": "Issue request registered successfully"
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

        cpf_enviado = issuer_data.get("cpf")
        cpf_do_certificado = None

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

                # 🆕 Extrai o CPF do certificado e compara
                subject = cert.subject.rfc4514_string()
                match = re.search(r":(\d{11})", subject)
                cpf_do_certificado = match.group(1) if match else None

                if not cpf_do_certificado:
                    return jsonify({"error_code": "ISSUERS_ERROR_020", "error_message": "CPF not found in certificate."}), 400
                if not cpf_enviado:
                    return jsonify({"error_code": "ISSUERS_ERROR_021", "error_message": "Missing field: cpf"}), 400
                if cpf_enviado != cpf_do_certificado:
                    return jsonify({
                        "error_code": "ISSUERS_ERROR_022",
                        "error_message": f"CPF in certificate ({cpf_do_certificado}) does not match the CPF provided ({cpf_enviado})."
                    }), 400

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
                issuer.disable_date = None
                message = "Issuer updated and enabled successfully."
            else:
                new_issuer = Issuer(
                    issuer_code=issuer_code_in_req,
                    cpf=cpf_enviado,
                    certificate=fingerprint,
                    password=encrypted_password,
                    certificate_expires_at=not_after,
                    active=True,
                    enable_date=datetime.utcnow()
                )
                db.session.add(new_issuer)
                issuer = new_issuer
                message = "Issuer created and enabled successfully."

        else:
            # Sem certificado, mas CPF foi enviado: comparar com o CPF no banco
            if cpf_enviado and issuer and issuer.cpf != cpf_enviado:
                return jsonify({
                    "error_code": "ISSUERS_ERROR_023",
                    "error_message": f"Provided CPF ({cpf_enviado}) does not match the issuer record ({issuer.cpf})."
                }), 400

            issuer.active = True
            issuer.disable_date = None
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
        issuer.disable_date = datetime.utcnow()
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
            "reason": receipt.reason,
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

        # Verifica se o status atual é 90
        status_is_90 = str(receipt.Status) == "90"

        # Atualiza os campos permitidos
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

        # Atualiza o status com regras específicas
        if "status" in data:
            new_status = str(data["status"])

            if status_is_90:
                if new_status == "99":
                    receipt.Status = new_status
                else:
                    return jsonify({
                        "error_code": "TASK_RETURN_ERROR_004",
                        "error_message": "Status can only be updated from 90 to 99."
                    }), 400
            else:
                receipt.Status = new_status

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
        
@api_bp.route('/test-callback', methods=['POST'])
@admin_token_required
def receber_callback_teste():
    """
    Endpoint para simular o servidor do cliente que recebe o callback.
    Além de logar os dados recebidos, valida se o issuer_code e o receipt_id existem no banco.
    """
    try:
        data = request.get_json()
        callback_data = data.get("data", {})

        receipt_id = callback_data.get("receipt_id")
        issuer_code = callback_data.get("issuer_code")

        if receipt_id is None or issuer_code is None:
            return jsonify({
                "error_code": "CALLBACK_RECEIVE_ERROR_001",
                "error_message": "receipt_id and issuer_code are required in 'data'."
            }), 400

        # Verifica se existe o recibo com os dados fornecidos
        receipt = Receipt.query.filter_by(
            issuer_code=str(issuer_code),
            receipt_id=receipt_id
        ).first()

        if not receipt:
            return jsonify({
                "error_code": "CALLBACK_RECEIVE_ERROR_002",
                "error_message": "Receipt not found for the given issuer_code and receipt_id."
            }), 404

        print("📥 Callback recebido no /teste-callback:")
        print(callback_data)

        return jsonify({
            "message": "Callback recebido com sucesso e validado.",
            "received_data": callback_data
        }), 200

    except Exception as e:
        return jsonify({
            "error_code": "CALLBACK_RECEIVE_ERROR_999",
            "error_message": "Erro inesperado ao processar callback.",
            "details": str(e)
        }), 500
        
@api_bp.route('/callback', methods=['GET'])
@admin_token_required
def listar_receipts_para_callback():
    """
    Lista até 100 receipts pendentes de callback, seja por emissão (status 10, callback null)
    ou por cancelamento (status 99, callback_cancel null).
    Retorna issuer.cpf + dados principais do recibo.
    """
    try:
        # Junta as duas condições com OR
        receipts = (
            db.session.query(Receipt, Issuer)
            .join(Issuer, Receipt.issuer_code == Issuer.issuer_code)
            .filter(
                db.or_(
                    db.and_(Receipt.Status == 10, Receipt.callback == None),
                    db.and_(Receipt.Status == 99, Receipt.callback_cancel == None)
                )
            )
            .limit(100)
            .all()
        )

        resultados = []
        for receipt, issuer in receipts:
            resultados.append({
                "issuer_cpf": issuer.cpf,
                "receipt": {
                    "issuer_code": receipt.issuer_code,
                    "receipt_id": receipt.receipt_id,
                    "date": receipt.date.isoformat() if receipt.date else None,
                    "test": receipt.test,
                    "status": receipt.Status,
                    "key": receipt.Chave,
                    "receipt_number": receipt.Numero
                }
            })

        return jsonify(resultados), 200

    except Exception as e:
        return jsonify({
            "error_code": "CALLBACK_LIST_ERROR",
            "error_message": "Erro ao buscar receipts para callback.",
            "details": str(e)
        }), 500
        
@api_bp.route('/callback-return', methods=['POST'])
@admin_token_required
def registrar_callback_recebido():
    """
    Recebe confirmação de que o callback foi enviado com sucesso.
    Atualiza a coluna 'callback' se status 10, ou 'callback_cancel' se status 99.
    Faz validações:
    - status deve ser igual ao registrado no banco
    - callback/callback_cancel não pode já estar preenchido
    """
    try:
        data = request.get_json()

        issuer_code = data.get("issuer_code")
        receipt_id = data.get("receipt_id")
        status = data.get("status")
        date_str = data.get("date")

        if None in [issuer_code, receipt_id, status, date_str]:
            return jsonify({
                "error_code": "CALLBACK_RETURN_ERROR_001",
                "error_message": "issuer_code, receipt_id, status, and date are required."
            }), 400

        # Converte a data recebida
        try:
            callback_date = datetime.fromisoformat(date_str)
        except Exception:
            return jsonify({
                "error_code": "CALLBACK_RETURN_ERROR_002",
                "error_message": "Invalid date format. Use ISO 8601."
            }), 400

        # Busca o recibo
        receipt = Receipt.query.filter_by(
            issuer_code=str(issuer_code),
            receipt_id=receipt_id
        ).first()

        if not receipt:
            return jsonify({
                "error_code": "CALLBACK_RETURN_ERROR_003",
                "error_message": "No receipt found with given issuer_code and receipt_id."
            }), 404

        # Verifica se o status do banco é o mesmo do informado
        if str(receipt.Status) != str(status):
            return jsonify({
                "error_code": "CALLBACK_RETURN_ERROR_004",
                "error_message": f"Status mismatch. Received: {status}, expected: {receipt.Status}."
            }), 400

        # Verifica e atualiza de acordo com o status
        if str(status) == "10":
            if receipt.callback is not None:
                return jsonify({
                    "error_code": "CALLBACK_RETURN_ERROR_005",
                    "error_message": "Callback already registered for status 10."
                }), 400
            receipt.callback = callback_date

        elif str(status) == "99":
            if receipt.callback_cancel is not None:
                return jsonify({
                    "error_code": "CALLBACK_RETURN_ERROR_006",
                    "error_message": "Callback already registered for status 99."
                }), 400
            receipt.callback_cancel = callback_date

        else:
            return jsonify({
                "error_code": "CALLBACK_RETURN_ERROR_007",
                "error_message": "Unsupported status. Only 10 or 99 are allowed."
            }), 400

        db.session.commit()

        return jsonify({
            "message": "Callback registrado com sucesso."
        }), 200

    except Exception as e:
        return jsonify({
            "error_code": "CALLBACK_RETURN_ERROR_999",
            "error_message": "Erro inesperado ao processar callback return.",
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