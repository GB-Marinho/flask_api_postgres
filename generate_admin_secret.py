import secrets

# Gera uma chave de 64 caracteres hexadecimais (256 bits)
secret = secrets.token_hex(32)

# Salva no arquivo .env
with open(".env", "a") as env_file:
    env_file.write(f"\nADMIN_JWT_SECRET_KEY={secret}\n")

print(f"✅ ADMIN_JWT_SECRET_KEY gerado e adicionado ao .env:\n{secret}")
