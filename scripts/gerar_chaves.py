"""Gera as chaves mestras (AS, Serviço) e salva em keys/."""

from os import path, urandom, makedirs

from common.config import TAMANHO_CHAVE, AS_MASTER_KEY_PATH, SVC_MASTER_KEY_PATH

_KEYS_DIR = path.dirname(AS_MASTER_KEY_PATH)
_CHAVE_PATHS = (AS_MASTER_KEY_PATH, SVC_MASTER_KEY_PATH)


def gerar_chaves(keys_dir: str | None = None) -> None:
    """Gera chaves aleatórias de TAMANHO_CHAVE bytes e salva em keys/, sobrescrevendo se já existirem.

    Args:
        keys_dir: Diretório onde salvar as chaves. Se None, usa o diretório padrão de AS_MASTER_KEY_PATH.
    """
    if keys_dir is None:
        keys_dir = _KEYS_DIR
    makedirs(keys_dir, exist_ok=True)
    for caminho in _CHAVE_PATHS:
        nome_arquivo = path.basename(caminho)
        caminho_saida = path.join(keys_dir, nome_arquivo)
        with open(caminho_saida, "wb") as arquivo:
            arquivo.write(urandom(TAMANHO_CHAVE))


def main():
    """Ponto de entrada do script de geracao de chaves."""
    gerar_chaves()


if __name__ == "__main__":
    main()
