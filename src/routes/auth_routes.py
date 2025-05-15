import os
from flask import Blueprint, request, jsonify
from src.auth.admin_jwt_auth import generate_admin_token
from src.auth.jwt_auth import generate_token
from datetime import datetime
from src.auth.auth_log import registrar_log_auth
from src.modules.models import MasterKeyAccess
from src.extensions import db

MASTER_KEY = os.getenv("MASTER_KEY", "default-key")
ADMIN_MASTER_KEY = os.getenv("ADMIN_MASTER_KEY", "default-admin-key")

auth_bp = Blueprint("auth_bp", __name__)

@auth_bp.route("/token", methods=["POST"])
def emitir_token():
    data = request.get_json()
    chave_recebida = data.get("master_key")
    ip = request.remote_addr
    chave_parcial = chave_recebida[:6] + "..." if chave_recebida else None

    if not chave_recebida:
        registrar_log_auth(ip, "fail", chave_parcial)
        return jsonify({
            "error_code": "AUTH_ERROR_001",
            "error_message": "Master key is required."
        }), 400

    if chave_recebida.strip() != MASTER_KEY.strip():
        registrar_log_auth(ip, "fail", chave_parcial)
        return jsonify({
            "error_code": "AUTH_ERROR_002",
            "error_message": "Invalid master key."
        }), 401

    registrar_log_auth(ip, "success", chave_parcial)

    token = generate_token("cliente_unico")

    ### print(f"[{datetime.now()}] ✅ Token issued successfully")

    return jsonify({
        "access_token": token,
        "token_type": "Bearer"
    }), 200

@auth_bp.route("/admin-token", methods=["POST"])
def emitir_token_admin():
    data = request.get_json()
    chave_recebida = data.get("admin_master_key")
    ip = request.remote_addr
    chave_parcial = chave_recebida[:6] + "..." if chave_recebida else None

    if not chave_recebida:
        registrar_log_auth(ip, "fail", chave_parcial)
        return jsonify({
            "error_code": "ADMIN_AUTH_ERROR_001",
            "error_message": "Admin master key is required."
        }), 400

    if chave_recebida.strip() != ADMIN_MASTER_KEY.strip():
        registrar_log_auth(ip, "fail", chave_parcial)
        return jsonify({
            "error_code": "ADMIN_AUTH_ERROR_002",
            "error_message": "Invalid admin master key."
        }), 401

    registrar_log_auth(ip, "success", chave_parcial)

    token = generate_admin_token("admin")  # Use "admin" or replace with ID/email

    ### print(f"[{datetime.now()}] ✅ Admin token issued successfully")

    return jsonify({
        "access_token": token,
        "token_type": "Bearer"
    }), 200
    
@auth_bp.route("/masterkey-generate", methods=["GET"])
def gerar_masterkey_uma_vez():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = datetime.utcnow()

    registro = MasterKeyAccess.query.first()

    if registro and registro.used:
        return jsonify({
            "error_code": "MASTERKEY_ERROR_001",
            "error_message": "This endpoint has already been accessed. The master key is no longer available."
        }), 403

    if not registro:
        registro = MasterKeyAccess(used=True, timestamp=now, ip=ip)
        db.session.add(registro)
    else:
        registro.used = True
        registro.timestamp = now
        registro.ip = ip

    db.session.commit()

    ### print(f"[{now}] 🔐 MASTER_KEY entregue via banco para IP {ip}.")

    return jsonify({
        "master_key": MASTER_KEY
    }), 200