import sys
import os
from flask import abort

# Garante que o diretório src esteja no caminho do Python
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask
from dotenv import load_dotenv

# Importa extensões (como db) após a modificação de caminho
from src.extensions import db

# Carrega variáveis de ambiente
load_dotenv()


def create_app():
    """Padrão de Fábrica de Aplicação"""
    app = Flask(__name__)

    # --- Configuração do Banco de Dados ---
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        # Trata URL do Postgres do Fly.io (substitui postgres:// por postgresql:// para SQLAlchemy)
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        elif database_url.startswith("mysql://"):
            # Garante uso de PyMySQL se for URL MySQL
            database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)

        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    else:
        # Alternativa para desenvolvimento local (SQLite)
        instance_path = os.path.join(app.instance_path)
        os.makedirs(instance_path, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = (
            f"sqlite:///{os.path.join(instance_path, 'local_dev.db')}"
        )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ✅ Configuração para manter conexões válidas e evitar erros após inatividade
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300  # segundos – recicla conexões antigas
    }

    # --- Inicializa Extensões ---
    db.init_app(app)

    # --- Importa e Registra Blueprints ---
    from src.routes.api_routes import api_bp

    app.register_blueprint(api_bp, url_prefix="/receita-saude/v1")

    from src.routes.auth_routes import auth_bp

    app.register_blueprint(auth_bp, url_prefix="/receita-saude/v1/auth")

    # --- Importa Models (para que sejam reconhecidos pelo SQLAlchemy antes do create_all) ---
    # Este import é necessário para que o Flask-Migrate ou create_all conheça os models.
    from src.modules import models

    # --- Rota Básica para Teste ---
    @app.route("/")
    #def hello_world():
    #    return "Flask API Status is running!"
    
    def home_blocked():
        abort(404)

    # --- Criação de tabelas no contexto da aplicação ---
    # Isso criará as tabelas com base nos models para o DB configurado (SQLite, Postgres, MySQL)
    
    with app.app_context():
        ### print("Garantindo existência das tabelas no banco...")
        db.create_all()
        ### print("Tabelas do banco verificadas/criadas.")

    """
    with app.app_context():
        print("Apagando todas as tabelas do banco...")
        db.drop_all()
        print("Tabelas removidas. Criando novamente...")
        db.create_all()
        print("Tabelas do banco recriadas.")
    """
    
    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 8080))
    # Use debug=True para desenvolvimento, mas garanta que esteja False ou removido em produção
    app.run(host="0.0.0.0", port=port, debug=False)
