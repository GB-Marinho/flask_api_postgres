from flask import Blueprint, request, jsonify
from src.extensions import db # Import db from extensions
from src.modules.models import RequestLog # Import the model
from src.modules.models import Recibo
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from src.modules.models import Emitente
from src.auth.jwt_auth import token_required

# Define the blueprint
status_bp = Blueprint(
    'status_bp', __name__
)

"""
@status_bp.route('/status', methods=['POST'])
def handle_status_request():
    
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    
    # --- Get user_id from request data --- 
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing 'user_id' in request data"}), 400
    
    # Log received data for debugging
    print(f"Received data for user_id {user_id}: {data}") 

    try:
        # Create a new log entry, now including the user_id
        new_log = RequestLog(user_id=str(user_id), status="received", message=data.get("message")) # Ensure user_id is stored as string
        new_log.set_data(data) # Store the full received JSON data
        
        # Add to session and commit to database
        db.session.add(new_log)
        db.session.commit()
        
        log_id = new_log.id # Get the ID of the newly created log
        print(f"Logged request with ID: {log_id} for user: {user_id}")

        response_status = {
            "status": "received_and_logged",
            "message": "Request processed and logged successfully.",
            "log_id": log_id,
            "user_id": user_id,
            "received_data": data
        }
        
        return jsonify(response_status), 200

    except Exception as e:
        db.session.rollback() # Rollback in case of error
        print(f"Error logging request for user {user_id}: {e}")
        return jsonify({"error": "Failed to process request", "details": str(e)}), 500
"""

@status_bp.route('/emitir-recibo', methods=['POST'])
@token_required
def emitir_recibo():
    """
    Endpoint para receber requisições com ações: emitir, cancelar ou consultar recibos.
    A ação é definida pelo campo "acao" presente dentro de "req".
    """
    
    cliente_id = request.cliente_id  # extraído do token
    print(f"Token válido para o cliente {cliente_id}")

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    req = data.get("req")

    if not req:
        return jsonify({"error": "Campo 'req' está ausente no corpo da requisição."}), 400

    acao = req.get("acao")
    cliente = req.get("cliente")

    if not acao:
        return jsonify({"error": "Campo 'acao' é obrigatório."}), 400
    if not cliente:
        return jsonify({"error": "Campo 'cliente' é obrigatório."}), 400

    emitente = Emitente.query.filter_by(codigo=cliente).first()
    if not emitente:
        print(f"[ERRO] Cliente '{cliente}' não encontrado.")
        return jsonify({"error": f"Cliente '{cliente}' não está registrado."}), 404
    
    novo = Recibo()
    try:
        novo.set_data_from_json(req)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    novo.set_data_from_json(req)
    db.session.add(novo)
    db.session.commit()
    

    # Validação dinâmica dos campos obrigatórios por tipo de ação
    campos_acao = {
        "emitir": ["acao", "id", "cliente", "pagador", "valor", "data", "descricao"],
        "cancelar": ["acao", "id", "cliente", "descricao"],
        "consultar": ["acao", "id", "cliente"]
    }

    required_fields = campos_acao.get(acao)
    if not required_fields:
        return jsonify({"error": f"Ação '{acao}' não suportada. Use 'emitir', 'cancelar' ou 'consultar'."}), 400

    missing_fields = [field for field in required_fields if field not in req]
    if missing_fields:
        return jsonify({"error": f"Campos obrigatórios ausentes: {', '.join(missing_fields)}"}), 400

    # Registro do log da requisição
    try:
        new_log = RequestLog(
            acao=acao,
            cliente=cliente,
            descricao=req.get("descricao", "")
        )
        new_log.set_data(data)
        db.session.add(new_log)
        db.session.commit()
        log_id = new_log.id
        print(f"[LOG] Ação '{acao}' registrada com sucesso para cliente '{cliente}'. log_id={log_id}")

    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"[ERRO] Falha ao registrar log da ação '{acao}': {e}")
        return jsonify({"error": "Erro ao registrar log", "detalhes": str(e)}), 500

    # Simulações de resposta por ação
    chave = "309C63F3-5F7D-4007-BD3B-53E3690E32B6"
    if acao == "emitir":
        arquivo = "https://www.exemplo.com/recibo-emitido.pdf"
        info = "Solicitação de emissão registrada com sucesso"
    elif acao == "cancelar":
        arquivo = "https://www.exemplo.com/recibo-cancelado.pdf"
        info = "Solicitação de cancelamento registrada com sucesso"
    elif acao == "consultar":
        arquivo = "https://www.exemplo.com/recibo.pdf"
        info = "Consulta realizada com sucesso"
    else:
        # Já foi tratado antes, mas por segurança:
        return jsonify({"error": "Ação inválida."}), 400

    return jsonify({
        "data": {
            "id": str(req["id"]),
            "cliente": cliente,
            "sucesso": True,
            "chave": chave,
            "arquivo": arquivo,
            "info": info,
            "log_id": log_id
        }
    }), 200


@status_bp.route("/test-db")
def test_db():
    try:
        result = db.session.execute(text("SELECT 1"))
        return "Conexão com MySQL ok!"
    except Exception as e:
        return f"Erro ao conectar: {str(e)}"