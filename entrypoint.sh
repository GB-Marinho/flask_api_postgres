#!/bin/bash
# entrypoint.sh

# Ativa o modo de falha imediata
set -e

# Roda as migrações
echo "⏳ Executando flask db upgrade..."
flask db upgrade

# Inicia o servidor
echo "🚀 Iniciando aplicação com Gunicorn..."
exec gunicorn --bind :8080 --workers 4 wsgi:app