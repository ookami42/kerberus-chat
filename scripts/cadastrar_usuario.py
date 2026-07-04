"""Adiciona um novo usuário ao user_db.json."""
from getpass import getpass
from os import urandom

from common.config import USER_DB_PATH, TAMANHO_SALT
from common.crypto import derivar_chave
from as_server.user_db import UserDB


def main():
    caminho = USER_DB_PATH
    banco = UserDB(caminho)

    print("\n\n### Cadastrar usuário ###")
    nome = input("Usuário: ")
    senha = getpass("Senha: ")

    if banco.buscar(nome) is not None:
        print(f"Usuário '{nome}' já existe.")
    else:
        salt = urandom(TAMANHO_SALT)
        hash_chave = derivar_chave(senha.encode(), salt)
        banco.cadastrar(nome, salt, hash_chave)
        print(f"Usuário {nome} cadastrado com sucesso!")


if __name__ == "__main__":
    main()
