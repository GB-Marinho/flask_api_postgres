from flask import Blueprint, request, jsonify
from src.extensions import db # Import db from extensions
from src.modules.models import RequestLog # Import the model

# Define the blueprint
status_bp = Blueprint(
    'status_bp', __name__
)

@status_bp.route('/status', methods=['POST'])
def handle_status_request():
    """Receives a JSON request including a user_id, logs it to the DB, 
       and returns a status.
    """
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
        new_log = RequestLog(user_id=str(user_id), status="received") # Ensure user_id is stored as string
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

