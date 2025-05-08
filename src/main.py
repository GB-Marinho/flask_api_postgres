import sys
import os
from flask import Flask

# Ensure the src directory is in the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import extensions (like db) after path modification
from src.extensions import db

# Importa o dotenv para carregar variáveis de ambiente
from dotenv import load_dotenv
load_dotenv()

def create_app():
    """Application Factory Pattern"""
    app = Flask(__name__)

    # --- Database Configuration --- 
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        # Handle Fly.io Postgres URL (replace postgres:// with postgresql:// for SQLAlchemy)
        print("Encontrado DATABASE_URL")  # Debugging line
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        # Keep the MySQL check for flexibility with external MySQL
        elif database_url.startswith("mysql://"):
            # Ensure PyMySQL is used if it's a MySQL URL (might need adjustment based on driver)
            database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)
        
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
        print(f"Using database: {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[1] if '@' in app.config['SQLALCHEMY_DATABASE_URI'] else 'SQLite or Unknown'}") # Log DB type without credentials
    else:
        # Fallback for local development (SQLite)
        print("WARNING: DATABASE_URL environment variable not set. Using default local SQLite DB.")
        instance_path = os.path.join(app.instance_path)
        os.makedirs(instance_path, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(instance_path, 'local_dev.db')}"

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # --- Initialize Extensions --- 
    db.init_app(app)

    # --- Import and Register Blueprints --- 
    from src.routes.status_routes import status_bp
    app.register_blueprint(status_bp, url_prefix="/")
    
    from routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    # --- Import Models (ensure they are known to SQLAlchemy before create_all) ---
    # This import is necessary so that Flask-Migrate or create_all knows about the models.
    from src.modules import models

    # --- Basic Route for Testing --- 
    @app.route("/")
    def hello_world():
        return "Flask API Status is running!"

    # --- Create DB tables within app context --- 
    # This will create tables based on models for the configured DB (SQLite, Postgres, MySQL)
    with app.app_context():
        print("Ensuring database tables exist...")
        db.create_all()
        print("Database tables checked/created.")

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 8080))
    # Use debug=True for development, but ensure it's False or removed for production
    app.run(host="0.0.0.0", port=port, debug=False) 

