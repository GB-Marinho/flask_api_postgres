from src.extensions import db
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import re

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
    test = db.Column(db.Boolean, default=False)
    reason = db.Column(db.String(255))
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
        self.receipt_id = int(data_dict.get("receipt_id", 0))
        self.payer = str(data_dict.get("payer", ""))
        self.beneficiary = str(data_dict.get("beneficiary", ""))

        amount_raw = data_dict.get("amount", "0")
        try:
            if isinstance(amount_raw, (int, float, Decimal)):
                self.amount = Decimal(str(amount_raw))
            else:
                amount_str = str(amount_raw).strip()
                if re.match(r"^\d{1,3}(\.\d{3})*(,\d{2})?$", amount_str) or re.match(r"^\d+(,\d{2})?$", amount_str):
                    normalized = amount_str.replace(".", "").replace(",", ".")
                    self.amount = Decimal(normalized)
                elif re.match(r"^\d+(\.\d{1,2})?$", amount_str):
                    self.amount = Decimal(amount_str)
                else:
                    raise ValueError
        except (InvalidOperation, ValueError):
            raise ValueError(f"Valor inválido: {amount_raw}. Use 9999,99 ou 9999.99")

        date_input = data_dict.get("date")
        if date_input:
            try:
                if isinstance(date_input, dict):
                    year = int(date_input.get("year"))
                    month = int(date_input.get("month"))
                    day = int(date_input.get("day"))
                    parsed_date = datetime(year, month, day).date()
                elif isinstance(date_input, date):
                    parsed_date = date_input if not isinstance(date_input, datetime) else date_input.date()
                elif isinstance(date_input, str):
                    try:
                        parsed_date = datetime.fromisoformat(date_input).date()
                    except ValueError:
                        parsed_date = datetime.strptime(date_input, "%d/%m/%Y").date()
                else:
                    raise ValueError

                if parsed_date < date(2025, 1, 1) or parsed_date > date.today():
                    raise ValueError("Date is outside the allowed emission period")

                self.date = parsed_date
            except Exception as e:
                raise ValueError(str(e))

        action = data_dict.get("action")
        if action == "issue" and "description" not in data_dict:
            raise ValueError("'description' field is required for action 'issue'")
        self.description = data_dict.get("description", "")

        if action == "cancel":
            self.reason = data_dict.get("reason")
        else:
            self.reason = None

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

class AdminTokenAtual(db.Model):
    __tablename__ = "admin_token_atuais"
    
    admin_id = db.Column(db.String, primary_key=True)
    jti = db.Column(db.String, nullable=False)
    
class MasterKeyAccess(db.Model):
    __tablename__ = "masterkey_access"

    id = db.Column(db.Integer, primary_key=True)
    used = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=True)
    ip = db.Column(db.String(45), nullable=True)  # Suporta IPv6 também