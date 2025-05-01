from src.extensions import db
from datetime import datetime
import json

class RequestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Add a column to store the user identifier. Indexed for faster lookups.
    user_id = db.Column(db.String(120), nullable=False, index=True)
    received_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    request_data = db.Column(db.Text, nullable=True) # Store JSON as text
    status = db.Column(db.String(50), nullable=False, default="received")

    def __repr__(self):
        return f"<RequestLog {self.id} for user {self.user_id} - {self.status} at {self.received_at}>"

    def set_data(self, data):
        """Sets the request data, converting dict to JSON string."""
        self.request_data = json.dumps(data)

    def get_data(self):
        """Gets the request data, converting JSON string back to dict."""
        if self.request_data:
            try:
                return json.loads(self.request_data)
            except json.JSONDecodeError:
                return None # Or handle error appropriately
        return None

