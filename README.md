# README - Sistema de API com Flask, MySQL e Fly.io

Este projeto implementa um sistema simples capaz de receber requisições JSON via API e retornar um status. A aplicação é construída com Flask, integra-se a um banco de dados MySQL e está configurada para ser executada em um contêiner Docker no Fly.io.

## Estrutura do Projeto

```
flask_api_status/
├── src/
│   ├── modules/
│   │   └── models.py         # Modelos de dados (RequestLog)
│   ├── routes/
│   │   └── status_routes.py  # Endpoints da API
│   ├── static/               # Arquivos estáticos (se necessário)
│   ├── extensions.py         # Inicialização de extensões (SQLAlchemy)
│   └── main.py               # Ponto de entrada da aplicação
├── venv/                     # Ambiente virtual Python (não versionado)
├── .dockerignore             # Arquivos a serem ignorados pelo Docker
├── Dockerfile                # Configuração para construção da imagem Docker
├── fly.toml                  # Configuração para deploy no Fly.io
├── requirements.txt          # Dependências Python
└── DEPLOYMENT.md             # Instruções detalhadas de implantação
```

## Funcionalidades

- **Endpoint `/api/status`**: Recebe requisições POST em formato JSON
- **Armazenamento em Banco de Dados**: Cada requisição é registrada no banco de dados MySQL
- **Resposta de Status**: Retorna um status confirmando o recebimento e processamento da requisição
- **Configuração para Docker**: Pronto para ser executado em contêineres
- **Preparado para Fly.io**: Configuração completa para deploy na plataforma Fly.io

## Requisitos

- Python 3.10+
- Flask
- Flask-SQLAlchemy
- PyMySQL
- Docker (para construção e teste local do contêiner)
- Conta no Fly.io (para implantação)

## Configuração Local

1. Clone o repositório
2. Crie e ative um ambiente virtual Python:
   ```bash
   python -m venv venv
   source venv/bin/activate  # No Windows: venv\Scripts\activate
   ```
3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
4. Execute a aplicação:
   ```bash
   python src/main.py
   ```
   A aplicação estará disponível em `http://localhost:8080`

## Testando a API Localmente

Você pode testar o endpoint da API usando curl ou qualquer cliente HTTP:

```bash
curl -X POST -H "Content-Type: application/json" \
     -d '{"message": "Teste", "valor": 123}' \
     http://localhost:8080/api/status
```

A resposta será algo como:

```json
{
  "status": "received_and_logged",
  "message": "Request processed and logged successfully.",
  "log_id": 1,
  "received_data": {
    "message": "Teste",
    "valor": 123
  }
}
```

## Implantação no Fly.io

Para instruções detalhadas sobre como implantar esta aplicação no Fly.io, incluindo a configuração do banco de dados MySQL, consulte o arquivo [DEPLOYMENT.md](DEPLOYMENT.md).

## Variáveis de Ambiente

- `DATABASE_URL`: URL de conexão com o banco de dados MySQL (formato: `mysql+pymysql://user:pass@host:port/db`)
- `PORT`: Porta em que a aplicação será executada (padrão: 8080)

## Notas Adicionais

- Em ambiente de produção, recomenda-se usar Gunicorn em vez do servidor de desenvolvimento do Flask
- A aplicação está configurada para usar SQLite localmente quando `DATABASE_URL` não está definida
- O Fly.io fornecerá automaticamente a variável `DATABASE_URL` quando um banco de dados MySQL for anexado à aplicação
