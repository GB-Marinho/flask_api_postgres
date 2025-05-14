from src.extensions import db
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

# Registra recibos no banco de dados 
class Receipt(db.Model):
    __tablename__ = 'receipts'

    idRS = db.Column(db.Integer, primary_key=True, autoincrement=True)
    received_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    issuer_code = db.Column(db.Integer, nullable=False)
    receipt_id = db.Column(db.Integer)
    payer = db.Column(db.String(15), nullable=False)
    beneficiary = db.Column(db.String(15), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    date = db.Column(db.Date)
    description = db.Column(db.String(255))
    Status = db.Column(db.SmallInteger, default=0)
    DataRS = db.Column(db.DateTime)
    Retorno = db.Column(db.DateTime)
    Chave = db.Column(db.String(50))
    Arquivo = db.Column(db.String(255))
    Excluido = db.Column(db.DateTime)
    Motivo = db.Column(db.String(255))
    Numero = db.Column(db.String(20))
    Obs = db.Column(db.String(255))
    Apuracao = db.Column(db.DateTime)

    def load_from_dict(self, data_dict):
        self.issuer_code = int(data_dict.get("issuer_code")) if data_dict.get("issuer_code") else None
        self.receipt_id = str(data_dict.get("receipt_id", ""))
        self.payer = str(data_dict.get("payer", ""))
        self.beneficiary = str(data_dict.get("beneficiary", ""))

        amount_str = str(data_dict.get("amount", "0")).replace(",", ".")
        try:
            self.amount = Decimal(amount_str)
        except InvalidOperation:
            raise ValueError(f"Valor inválido: {amount_str}")

        date_str = data_dict.get("date")
        if date_str:
            try:
                self.date = datetime.strptime(date_str, "%d/%m/%Y").date()
            except ValueError:
                raise ValueError(f"Data inválida: {date_str}. Use o formato dd/mm/aaaa.")

        self.description = data_dict.get("description", "")

# Tabela para armazenar os issuers (clientes) que podem emitir recibos
class Issuer(db.Model):
    __tablename__ = 'issuers'

    id = db.Column(db.Integer, primary_key=True)
    issuer_code = db.Column(db.String(255), nullable=False, unique=True)
    cpf = db.Column(db.String(11), nullable=False)
    certificate = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=True)
    certificate_expires_at = db.Column(db.DateTime, nullable=True)

# Log de todas as tentativas de autenticação
class AuthLog(db.Model):
    __tablename__ = "auth_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    ip = db.Column(db.String(45), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    chave_parcial = db.Column(db.String(20), nullable=True)

# Guarda o jti (JWT ID) para controle de revogação de tokens
class TokenAtual(db.Model):
    __tablename__ = "token_atuais"
    
    issuer_code = db.Column(db.String(50), primary_key=True)
    jti = db.Column(db.String(32), nullable=False)

# Guarda URLs de callback para notificações
class EndpointUrl(db.Model):
    __tablename__ = "endpoint_urls"

    id = db.Column(db.Integer, primary_key=True)
    issuer_code = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    token = db.Column(db.String(512), nullable=False)
    ip = db.Column(db.String(100), nullable=False)
    data = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
