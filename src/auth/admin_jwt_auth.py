import os
import jwt
import secrets
from datetime import datetime, timezone
from flask import request, jsonify
from functools import wraps
from src.extensions import db
from src.modules.models import AdminTokenAtual

# === Configuração ===
ADMIN_SECRET_KEY = os.getenv("ADMIN_JWT_SECRET_KEY", "admin-secret-key-default")


# === Emissão de token JWT para admin ===
def generate_admin_token(admin_id: str) -> str:
    """
    Gera e salva um token JWT para o administrador informado.
    """
    jti = secrets.token_hex(16)

    payload = {
        "sub": admin_id,
        "role": "admin",
        "jti": jti,
        "iat": datetime.now(timezone.utc)
    }

    token = jwt.encode(payload, ADMIN_SECRET_KEY, algorithm="HS256")
    _salvar_admin_token_valido(admin_id, jti)
    return token


# === Decorador para rotas protegidas com token admin ===
def admin_token_required(f):
    """
    Valida o token JWT enviado no cabeçalho Authorization (Bearer).
    Acesso apenas se o token estiver ativo na base de dados.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token ausente ou inválido"}), 401

        token = auth_header.split()[1]

        try:
            decoded = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=["HS256"])
            admin_id = decoded.get("sub")
            jti = decoded.get("jti")

            # Verifica se o jti ainda é o válido para esse admin_id
            token_registrado = db.session.get(AdminTokenAtual, admin_id)

            if not token_registrado or token_registrado.jti != jti:
                return jsonify({"error": "Token revogado"}), 401

            # Anexa admin_id à requisição (caso útil para a rota)
            request.admin_id = admin_id

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401

        return f(*args, **kwargs)

    return decorated


# === Função privada para persistir token válido ===
def _salvar_admin_token_valido(admin_id: str, jti: str):
    """
    Atualiza ou cria o token válido mais recente para o admin_id.
    """
    token = db.session.get(AdminTokenAtual, admin_id)

    if token:
        token.jti = jti
    else:
        token = AdminTokenAtual(admin_id=admin_id, jti=jti)
        db.session.add(token)

    db.session.commit()
