import secrets

def gerar_chave(nome, tamanho=64):
    return f"{nome}={secrets.token_urlsafe(tamanho)}"

linhas = [
    gerar_chave("FLASK_SECRET_KEY"),
    gerar_chave("JWT_SECRET_KEY")
]

with open(".env", "w") as f:
    f.write("\n".join(linhas) + "\n")

print("✅ Arquivo .env gerado com sucesso!")
print("🔒 Suas chaves:")
for linha in linhas:
    print("  ", linha)
