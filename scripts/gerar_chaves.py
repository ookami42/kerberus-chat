"""Gera as 3 chaves mestras (AS, TGS, Serviço) e salva em keys/."""

import os

_KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys")

_NOMES_CHAVES = ("as_master.key", "tgs_master.key", "service_master.key")


def gerar_chaves() -> None:
    """Gera 3 chaves aleatórias de 16 bytes e salva em keys/, sobrescrevendo se já existirem."""
    os.makedirs(_KEYS_DIR, exist_ok=True)
    for nome_arquivo in _NOMES_CHAVES:
        caminho = os.path.join(_KEYS_DIR, nome_arquivo)
        with open(caminho, "wb") as arquivo:
            arquivo.write(os.urandom(16))


if __name__ == "__main__":
    gerar_chaves()
