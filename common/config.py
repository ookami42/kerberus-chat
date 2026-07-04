"""Constantes do projeto: portas, hosts, tamanhos de chave, lifetime."""
AS_HOST     = "127.0.0.1"
AS_PORT     = 5450
TGS_HOST    = "127.0.0.1"
TGS_PORT    = 5451
SVC_HOST    = "127.0.0.1"
SVC_PORT    = 5452
TAMANHO_CHAVE = 16     # 128 bits
TAMANHO_SALT = 16
TAMANHO_NONCE = 12
LIFETIME_TICKET = 480  # minutos (8h)
JANELA_AUTH = 300      # segundos (5 min)
USER_DB_PATH = "data/user_db.json"