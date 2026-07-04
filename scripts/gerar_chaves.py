"""Gera as 3 chaves mestras (AS, TGS, Serviço) e salva em keys/."""

import os

_KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys")

_NOMES_CHAVES = ("as_master.key", "tgs_master.key", "service_master.key")


def gerar_chaves(keys_dir: str | None = None) -> None:
    """Gera 3 chaves aleatórias de 16 bytes e salva em keys/, sobrescrevendo se já existirem.

    Args:
        keys_dir: Diretório onde salvar as chaves. Se None, usa o diretório padrão keys/.
    """
    if keys_dir is None:
        keys_dir = _KEYS_DIR
    os.makedirs(keys_dir, exist_ok=True)
    for nome_arquivo in _NOMES_CHAVES:
        caminho = os.path.join(keys_dir, nome_arquivo)
        with open(caminho, "wb") as arquivo:
            arquivo.write(os.urandom(16))


if __name__ == "__main__":
    gerar_chaves()
