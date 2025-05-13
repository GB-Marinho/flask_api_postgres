from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from datetime import datetime

def validar_certificado_pfx(pfx_bytes: bytes, senha: str):
    try:
        # Carrega o conteúdo do .pfx
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
            data=pfx_bytes,
            password=senha.encode() if senha else None
        )

        if cert is None:
            return False, "Certificado inválido ou ausente no arquivo PFX."

        # Verifica validade temporal
        now = datetime.utcnow()
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after

        if now < not_before:
            return False, f"Certificado ainda não é válido. Início: {not_before}"
        if now > not_after:
            return False, f"Certificado expirado em: {not_after}"

        return True, f"Certificado válido. Expira em {not_after}"

    except ValueError as e:
        return False, f"Erro de senha ou estrutura do arquivo: {e}"
    except Exception as e:
        return False, f"Erro inesperado: {e}"
