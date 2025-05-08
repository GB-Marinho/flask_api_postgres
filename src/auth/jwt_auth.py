import os
import jwt
from datetime import datetime, timedelta
from flask import request, jsonify
from functools import wraps
import secrets
from src.extensions import db

from src.modules.models import TokenAtual

SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# === Emissão de token ===
def generate_token(cliente_id):
    jti = secrets.token_hex(16)
    payload = {
        "sub": cliente_id,
        "jti": jti,
        "iat": datetime.utcnow()
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    salvar_token_valido(cliente_id, jti)  # ← esta função abaixo
    return token

# === Validação de token ===
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token ausente ou inválido"}), 401

        token = auth_header.split()[1]
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            jti = decoded.get("jti")
            cliente = decoded.get("sub")

            # Verifica se o jti ainda é o válido
            token_armazenado = TokenAtual.query.get(cliente)
            if not token_armazenado or token_armazenado.jti != jti:
                return jsonify({"error": "Token revogado"}), 401

            request.cliente_id = cliente

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401

        return f(*args, **kwargs)
    return decorated

def salvar_token_valido(cliente, jti):
    registro = TokenAtual.query.get(cliente)
    if registro:
        registro.jti = jti
    else:
        registro = TokenAtual(cliente=cliente, jti=jti)
        db.session.add(registro)
    db.session.commit()