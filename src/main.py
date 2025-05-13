import sys
import os

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
        print("Encontrado DATABASE_URL")  # Linha de depuração
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        # Mantém verificação do MySQL para flexibilidade com MySQL externo
        elif database_url.startswith("mysql://"):
            # Garante uso de PyMySQL se for URL MySQL
            database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)

        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
        print(
            f"Usando banco de dados: "
            f"{app.config['SQLALCHEMY_DATABASE_URI'].split('@')[1] if '@' in app.config['SQLALCHEMY_DATABASE_URI'] else 'SQLite ou Desconhecido'}"
        )  # Exibe tipo do DB sem credenciais
    else:
        # Alternativa para desenvolvimento local (SQLite)
        print("AVISO: variável DATABASE_URL não definida. Usando SQLite local padrão.")
        instance_path = os.path.join(app.instance_path)
        os.makedirs(instance_path, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = (
            f"sqlite:///{os.path.join(instance_path, 'local_dev.db')}"
        )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # --- Inicializa Extensões ---
    db.init_app(app)

    # --- Importa e Registra Blueprints ---
    from src.routes.api_routes import api_bp

    app.register_blueprint(api_bp, url_prefix="/")

    from src.routes.auth_routes import auth_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")

    # --- Importa Models (para que sejam reconhecidos pelo SQLAlchemy antes do create_all) ---
    # Este import é necessário para que o Flask-Migrate ou create_all conheça os models.
    from src.modules import models

    # --- Rota Básica para Teste ---
    @app.route("/")
    def hello_world():
        return "Flask API Status is running!"

    # --- Criação de tabelas no contexto da aplicação ---
    # Isso criará as tabelas com base nos models para o DB configurado (SQLite, Postgres, MySQL)
    with app.app_context():
        print("Garantindo existência das tabelas no banco...")
        db.create_all()
        print("Tabelas do banco verificadas/criadas.")

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 8080))
    # Use debug=True para desenvolvimento, mas garanta que esteja False ou removido em produção
    app.run(host="0.0.0.0", port=port, debug=False)
