from cryptography.fernet import Fernet

if __name__ == "__main__":
    key = Fernet.generate_key().decode()          # gera a chave e decodifica para string
    print(f"FERNET_KEY={key}")                     # já no formato VAR=VAL para o seu .env
