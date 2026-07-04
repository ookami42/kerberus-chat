"""Gerenciamento de usuários: cadastro, busca, validação de senha."""
import json
from os import path, makedirs
from typing import TypedDict


class UserEntry(TypedDict):
    salt: str
    hash_chave: str


class UserDB:
    """Gerencia o arquivo user_db.json com usuários e suas chaves derivadas."""

    def __init__(self, caminho: str):
        """Carrega o banco de usuários do arquivo JSON.

        Inicia com um dicionário vazio, se o caminho existir, carrega os dados do json.

        Args:
            caminho: Caminho para o arquivo JSON.
        """
        self._dados: dict[str, dict[str, UserEntry]] = {"users": {}}
        self._caminho = caminho
        if path.exists(caminho):
            with open(caminho, "r") as f:
                self._dados = json.load(f)

    def buscar(self, nome: str) -> UserEntry | None:
        """Retorna os dados de um usuário ou None se não existir.

        Args:
            nome: Nome do usuário.

        Returns:
            dict com chaves "salt" e "hash_chave" (strings hex) ou None.
        """
        return self._dados["users"].get(nome)

    def cadastrar(self, nome: str, salt: bytes, hash_chave: bytes):
        """Adiciona ou atualiza um usuário e persiste no arquivo.

        Args:
            nome: Nome do usuário.
            salt: Salt aleatório de 16 bytes.
            hash_chave: Chave derivada (PBKDF2) de 16 bytes.
        """ 
        self._dados["users"][nome] = {
            "salt": salt.hex(),
            "hash_chave": hash_chave.hex(),
        }
        self._salvar()

    def _salvar(self):
        """Persiste o dicionário no arquivo JSON."""
        makedirs(path.dirname(self._caminho), exist_ok=True)
        with open(self._caminho, "w") as f:
            json.dump(self._dados, f, indent=2)
