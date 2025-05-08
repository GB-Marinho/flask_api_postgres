import secrets

def gerar_master_key():
    chave = secrets.token_urlsafe(64)
    print("\n🔐 MASTER_KEY gerada com segurança:\n")
    print(f"MASTER_KEY={chave}")
    print("\nCopie e cole essa chave no seu arquivo .env no servidor.")

if __name__ == "__main__":
    gerar_master_key()
