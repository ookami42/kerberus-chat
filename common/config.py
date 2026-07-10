"""Constantes do projeto: portas, hosts, tamanhos de chave, lifetime.

Os caminhos de arquivo (chaves, banco de usuarios) sao resolvidos
a partir da localizacao deste modulo, garantindo que funcionem
independentemente do diretorio de trabalho.
"""

from pathlib import Path

# --- Raiz do projeto (2 niveis acima de common/config.py) ---
_RAIZ = Path(__file__).resolve().parent.parent

# --- Rede ---
AS_HOST     = "127.0.0.1"
AS_PORT     = 5450
TGS_HOST    = "127.0.0.1"
TGS_PORT    = 5451
SVC_HOST    = "127.0.0.1"
SVC_PORT    = 5452

# --- Criptografia ---
TAMANHO_CHAVE = 16     # 128 bits
TAMANHO_SALT  = 16
TAMANHO_NONCE = 12

# --- Tickets ---
LIFETIME_TICKET = 480  # minutos (8h)
JANELA_AUTH = 300      # segundos (5 min)

# --- Caminhos (resolvidos absolutamente) ---
USER_DB_PATH        = str(_RAIZ / "data" / "user_db.json")
AS_MASTER_KEY_PATH   = str(_RAIZ / "keys" / "as_master.key")
SVC_MASTER_KEY_PATH  = str(_RAIZ / "keys" / "service_master.key")
NOTAS_RAIZ_PATH     = str(_RAIZ / "data" / "notas")
