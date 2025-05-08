from src.extensions import db
from datetime import datetime
from flask import request
from src.modules.models import AuthLog
from src.extensions import db

def registrar_log_auth(ip, status, chave_parcial=None):
    log = AuthLog(
        ip=ip,
        status=status,
        chave_parcial=chave_parcial
    )
    db.session.add(log)
    db.session.commit()