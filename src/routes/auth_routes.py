import os
from flask import Blueprint, request, jsonify
from src.auth.jwt_auth import generate_token
from datetime import datetime
from src.auth.auth_log import registrar_log_auth

MASTER_KEY = os.getenv("MASTER_KEY")

auth_bp = Blueprint("auth_bp", __name__)

@auth_bp.route("/auth/token", methods=["POST"])
def emitir_token():
    data = request.get_json()
    chave_recebida = data.get("master_key")
    ip = request.remote_addr
    chave_parcial = chave_recebida[:6] + "..." if chave_recebida else None

    if not chave_recebida:
        registrar_log_auth(ip, "fail", chave_parcial)
        return jsonify({"error": "Chave mestra obrigatória"}), 400

    if chave_recebida.strip() != MASTER_KEY.strip():
        registrar_log_auth(ip, "fail", chave_parcial)
        return jsonify({"error": "Chave inválida"}), 401
    
    registrar_log_auth(ip, "success", chave_parcial)

    token = generate_token("cliente_unico")

    print(f"[{datetime.now()}] ✅ Token emitido com sucesso")
    
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
    })
