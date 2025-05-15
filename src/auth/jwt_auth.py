import os
import jwt
from datetime import datetime, timezone
from flask import request, jsonify
from functools import wraps
import secrets
from src.extensions import db

from src.modules.models import TokenAtual

SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# === Emissão de token ===
def generate_token(issuer_code):
    jti = secrets.token_hex(16)
    payload = {
        "sub": issuer_code,
        "jti": jti,
        "iat": datetime.now(timezone.utc)
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    salvar_token_valido(issuer_code, jti)  # ← esta função abaixo
    return token

# === Validação de token ===
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({
                "error_code": "AUTH_ERROR_003",
                "error_message": "Missing or invalid Authorization header."
            }), 401

        token = auth_header.split()[1]

        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            jti = decoded.get("jti")
            issuer_code = decoded.get("sub")

            # Verifica se o jti ainda é válido
            token_armazenado = db.session.get(TokenAtual, issuer_code)
            if not token_armazenado or token_armazenado.jti != jti:
                return jsonify({
                    "error_code": "AUTH_ERROR_004",
                    "error_message": "Token has been revoked."
                }), 401

            request.issuer_code = issuer_code

        except jwt.ExpiredSignatureError:
            return jsonify({
                "error_code": "AUTH_ERROR_005",
                "error_message": "Token has expired."
            }), 401

        except jwt.InvalidTokenError:
            return jsonify({
                "error_code": "AUTH_ERROR_006",
                "error_message": "Invalid token."
            }), 401

        return f(*args, **kwargs)
    return decorated

def salvar_token_valido(issuer_code, jti):
    registro = db.session.get(TokenAtual, issuer_code)
    if registro:
        registro.jti = jti
    else:
        registro = TokenAtual(issuer_code=issuer_code, jti=jti)
        db.session.add(registro)
    db.session.commit()