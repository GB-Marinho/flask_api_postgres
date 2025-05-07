# Instruções de Implantação: Flask no Fly.io + Fly Postgres

Este documento descreve os passos para implantar a aplicação Flask `flask_api_status` na plataforma Fly.io, utilizando o serviço de banco de dados Postgres gerenciado pelo Fly.io.

Esta é a abordagem recomendada, pois o Fly Postgres é estável, bem integrado e oferece um plano gratuito generoso.

## Pré-requisitos

1.  **Conta no Fly.io:** Você precisa ter uma conta ativa no [Fly.io](https://fly.io/).
2.  **`flyctl` CLI:** Instale a ferramenta de linha de comando do Fly.io (`flyctl`) seguindo as instruções [aqui](https://fly.io/docs/hands-on/install-flyctl/) e faça login com `fly auth login`.
3.  **Docker:** Ter o Docker instalado localmente ([Docker Desktop](https://www.docker.com/products/docker-desktop/)) pode ser útil para testes, embora não estritamente necessário para o deploy no Fly.io.
4.  **Git:** O código do projeto `flask_api_status` (incluindo o `requirements.txt` atualizado com `psycopg2-binary`) deve estar em um repositório Git.

## Passos para Implantação

1.  **Navegue até o Projeto:**
    *   Abra seu terminal e navegue até o diretório raiz do projeto `flask_api_status`.

2.  **Inicialize o App Fly.io (se ainda não feito):**
    *   Execute: `fly launch`
    *   **Nome do App:** Escolha um nome único (ex: `flask-api-status`).
    *   **Organização:** Selecione sua organização Fly.io.
    *   **Região:** Escolha uma região (ex: `gru`).
    *   **Banco de Dados Postgres:** O `flyctl` perguntará se você deseja configurar um banco de dados Postgres. Responda **SIM** (y).
        *   Siga as instruções para escolher um nome para o cluster Postgres (ex: `flask-api-status-db`), a região (idealmente a mesma da aplicação) e a configuração da VM.
    *   **Deploy Agora:** Perguntará se deseja implantar imediatamente. Você pode responder **SIM** (y) ou **NÃO** (n). Se responder não, você precisará executar `fly deploy` manualmente no passo 4.
    *   Este comando criará/confirmará o `fly.toml`, registrará o app no Fly.io e, se você respondeu sim para Postgres, provisionará e anexará o banco de dados.

3.  **Verifique a Conexão do Banco de Dados (se provisionado no passo 2):**
    *   O comando `fly launch` (ou `fly postgres attach` se feito separadamente) deve ter configurado automaticamente a variável de ambiente `DATABASE_URL` como um *secret* na sua aplicação Flask.
    *   Verifique se o secret foi criado:
      ```bash
      fly secrets list -a <flask-app-name>
      ```
    *   A `DATABASE_URL` deve começar com `postgres://` ou `postgresql://`. O código em `src/main.py` já está preparado para lidar com ambos os formatos.

4.  **Faça o Deploy da Aplicação (se não feito no passo 2):**
    *   Se você respondeu "NÃO" para "Deploy Agora?" no `fly launch`, execute o deploy manualmente:
      ```bash
      fly deploy -a <flask-app-name>
      ```
    *   O Fly.io construirá a imagem Docker usando seu `Dockerfile` (que inclui a instalação do `psycopg2-binary`) e iniciará a aplicação.

5.  **Teste a Aplicação Implantada:**
    *   Obtenha a URL pública:
      ```bash
      fly status -a <flask-app-name>
      # Ou abra no navegador:
      fly open -a <flask-app-name>
      ```
    *   A página inicial deve mostrar "Flask API Status is running!".
    *   Envie uma requisição POST para o endpoint `/api/status` usando `curl` ou outra ferramenta, incluindo o `user_id`:
      ```bash
      curl -X POST -H "Content-Type: application/json" -d '{"user_id": "fly_user_789", "message": "Test on Fly.io with Postgres"}' https://flask-api-postgres.fly.dev/api/status 
      ```
    *   Verifique se a resposta JSON indica sucesso (`status: received_and_logged`) e inclui o `log_id` e o `user_id`.
    *   Monitore os logs da aplicação para verificar se a conexão com o banco ocorreu e se há erros:
      ```bash
      fly logs -a <flask-app-name>
      ```

## Considerações Adicionais

*   **Gunicorn:** Para produção, considere usar Gunicorn conforme descrito no `README.md` (atualizando o `Dockerfile` e `requirements.txt`).
*   **Migrações:** Para alterações futuras no esquema do banco de dados, considere usar uma ferramenta de migração como Flask-Migrate (que precisaria ser adicionada ao projeto).

Seguindo estes passos, sua aplicação Flask rodando no Fly.io estará conectada ao banco de dados Fly Postgres, pronta para receber e registrar logs por usuário.
