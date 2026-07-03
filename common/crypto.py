"""Primitivas criptográficas: AES-GCM, PBKDF2, utilitários."""
from os import urandom
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def cifrar_aes_gcm(chave: bytes, texto_plano: bytes) -> bytes:
    """Cifra dados com AES-GCM.

    Gera um nonce aleatório de 12 bytes, cifra o texto plano e retorna
    nonce + texto_cifrado num único pacote.

    Args:
        chave: Chave AES de 16 bytes (128 bits).
        texto_plano: Dados a cifrar.

    Returns:
        bytes: nonce (12 bytes) concatenado ao texto cifrado.
    """
    aesgcm = AESGCM(chave)
    nonce = urandom(12)
    texto_cifrado = aesgcm.encrypt(nonce, texto_plano, associated_data=None)
    return nonce + texto_cifrado

def decifrar_aes_gcm(chave: bytes, pacote: bytes) -> bytes:
    """Decifra dados cifrados com AES-GCM.

    Extrai o nonce (12 bytes) do início do pacote e decifra o restante.

    Args:
        chave: Chave AES de 16 bytes (128 bits).
        pacote: nonce (12 bytes) + texto cifrado.

    Returns:
        bytes: Texto plano decifrado.

    Raises:
        InvalidTag: Se a cifra foi violada ou a chave está incorreta.
    """
    aesgcm = AESGCM(chave)
    nonce = pacote[:12]
    texto_cifrado = pacote[12:]
    return aesgcm.decrypt(nonce, texto_cifrado, associated_data=None)


def derivar_chave(senha: bytes, salt: bytes) -> bytes:
    """Deriva uma chave de 128 bits a partir de senha e salt usando PBKDF2-HMAC-SHA256.

    Args:
        senha: Senha do usuário em bytes.
        salt: Salt aleatório em bytes.

    Returns:
        bytes: Chave derivada de 16 bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(senha)