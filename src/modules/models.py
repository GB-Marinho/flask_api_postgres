from src.extensions import db
from datetime import datetime
import json
from decimal import Decimal, InvalidOperation
from datetime import datetime

"""
class RequestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Add a column to store the user identifier. Indexed for faster lookups.
    user_id = db.Column(db.String(120), nullable=False, index=True)
    message = db.Column(db.String(255), nullable=True) # Optional message field
    received_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    request_data = db.Column(db.Text, nullable=True) # Store JSON as text
    status = db.Column(db.String(50), nullable=False, default="received")

    def __repr__(self):
        return f"<RequestLog {self.id} for user {self.user_id} - {self.status} at {self.received_at}>"

    def set_data(self, data):
        self.request_data = json.dumps(data)

    def get_data(self):
        if self.request_data:
            try:
                return json.loads(self.request_data)
            except json.JSONDecodeError:
                return None # Or handle error appropriately
        return None
"""

# Recebe requisições JSON e registra no banco de dados. - ANTIGO
class RequestLog(db.Model):
    __tablename__ = 'request_logs'

    id = db.Column(db.Integer, primary_key=True)
    acao = db.Column(db.String(20), nullable=False)
    cliente = db.Column(db.String(50), nullable=False)
    descricao = db.Column(db.Text, nullable=True)
    received_at = db.Column(db.DateTime, default=datetime.utcnow)
    request_data = db.Column(db.Text, nullable=False)

    def set_data(self, data_dict):
        self.request_data = json.dumps(data_dict, ensure_ascii=False)

# Registra recibos no banco de dados
class Recibo(db.Model):
    __tablename__ = 'recibos'  # ou o nome real da tabela, caso seja diferente

    idRS = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Inicio = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    Cliente = db.Column(db.Integer, nullable=False)
    idRecibo = db.Column(db.Integer)
    Codigo = db.Column(db.String(20), nullable=False)
    Pagador = db.Column(db.String(15), nullable=False)
    Beneficiario = db.Column(db.String(15), nullable=False)
    Valor = db.Column(db.Numeric(10, 2), nullable=False)
    Data = db.Column(db.Date)
    Descricao = db.Column(db.String(255))
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
    Request_data = db.Column(db.Text, nullable=False)

    def set_data_from_json(self, data_dict):
        """
        Método opcional para preencher os campos automaticamente a partir de um dicionário.
        """
        self.Cliente = int(data_dict.get("cliente")) if data_dict.get("cliente") else None
        self.Codigo = str(data_dict.get("codigo", ""))
        self.Pagador = str(data_dict.get("pagador", ""))
        self.Beneficiario = str(data_dict.get("beneficiario", ""))

        # Valor: "9999,99" → Decimal("9999.99")
        valor_str = str(data_dict.get("valor", "0")).replace(",", ".")
        try:
            self.Valor = Decimal(valor_str)
        except InvalidOperation:
            raise ValueError(f"Valor inválido: {valor_str}")

        # Data: "13/01/2025" → datetime.date
        data_str = data_dict.get("data")
        if data_str:
            try:
                self.Data = datetime.strptime(data_str, "%d/%m/%Y").date()
            except ValueError:
                raise ValueError(f"Data inválida: {data_str}. Use o formato dd/mm/aaaa.")

        self.Descricao = data_dict.get("descricao")
        self.Motivo = data_dict.get("motivo")
        self.Obs = data_dict.get("obs")
        self.Numero = data_dict.get("numero")

        # Armazena o JSON completo da requisição
        self.Request_data = json.dumps(data_dict, ensure_ascii=False)
        
# Consulta se o cliente já existe no banco de dados.
class Emitente(db.Model):
    __tablename__ = 'emitentes'

    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(255), nullable=False, unique=True)
    cpf = db.Column(db.String(11), nullable=False)
    certificado = db.Column(db.String(255), nullable=False)
    senha = db.Column(db.String(255), nullable=False)