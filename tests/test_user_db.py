"""Testes unitários para as_server/user_db.py.

Testa a classe UserDB: inicialização, cadastro e busca de usuários
conforme especificação da issue #9. Usa diretórios temporários para
evitar poluir o banco de dados real.
"""

import json
import os
import tempfile

from as_server.user_db import UserDB
from common.config import TAMANHO_CHAVE


def _caminho_tmp():
    """Gera um caminho temporário que não existe ainda."""
    tmp_dir = tempfile.mkdtemp()
    return os.path.join(tmp_dir, "test.json")


class TestUserDBInit:
    """Testes de inicialização do UserDB."""

    def test_inicia_vazio_sem_arquivo(self):
        """Caminho inexistente deve iniciar com dict vazio."""
        caminho = _caminho_tmp()
        banco = UserDB(caminho)
        assert banco._dados == {"users": {}}

    def test_carrega_json_existente(self):
        """Arquivo JSON válido é carregado corretamente."""
        caminho = _caminho_tmp()
        with open(caminho, "w") as f:
            json.dump({"users": {"alice": {"salt": "ab", "hash_chave": "cd"}}}, f)

        banco = UserDB(caminho)
        resultado = banco.buscar("alice")
        assert resultado is not None
        assert resultado["salt"] == "ab"
        assert resultado["hash_chave"] == "cd"

        os.unlink(caminho)


class TestUserDBBuscar:
    """Testes do método buscar."""

    def test_usuario_existente_retorna_dict(self):
        """Buscar usuário cadastrado retorna seus dados."""
        caminho = _caminho_tmp()
        banco = UserDB(caminho)
        salt = os.urandom(TAMANHO_CHAVE)
        hash_chave = os.urandom(TAMANHO_CHAVE)
        banco.cadastrar("bob", salt, hash_chave)

        resultado = banco.buscar("bob")
        assert resultado is not None
        assert resultado["salt"] == salt.hex()
        assert resultado["hash_chave"] == hash_chave.hex()

        os.unlink(caminho)

    def test_usuario_inexistente_retorna_none(self):
        """Buscar usuário não cadastrado retorna None."""
        caminho = _caminho_tmp()
        banco = UserDB(caminho)
        assert banco.buscar("inexistente") is None


class TestUserDBCadastrar:
    """Testes do método cadastrar."""

    def test_adiciona_em_memoria(self):
        """Cadastrar adiciona o usuário no dicionário em memória."""
        caminho = _caminho_tmp()
        banco = UserDB(caminho)
        salt = os.urandom(TAMANHO_CHAVE)
        hash_chave = os.urandom(TAMANHO_CHAVE)
        banco.cadastrar("carol", salt, hash_chave)

        assert "carol" in banco._dados["users"]
        assert banco._dados["users"]["carol"]["salt"] == salt.hex()
        assert banco._dados["users"]["carol"]["hash_chave"] == hash_chave.hex()

        os.unlink(caminho)

    def test_persiste_no_arquivo(self):
        """Cadastrar persiste os dados e outra instância consegue ler."""
        caminho = _caminho_tmp()
        banco1 = UserDB(caminho)
        salt = os.urandom(TAMANHO_CHAVE)
        hash_chave = os.urandom(TAMANHO_CHAVE)
        banco1.cadastrar("dave", salt, hash_chave)

        banco2 = UserDB(caminho)
        resultado = banco2.buscar("dave")
        assert resultado is not None
        assert resultado["salt"] == salt.hex()
        assert resultado["hash_chave"] == hash_chave.hex()

        os.unlink(caminho)

    def test_sobrescreve_usuario(self):
        """Cadastrar mesmo nome sobrescreve dados anteriores."""
        caminho = _caminho_tmp()
        banco = UserDB(caminho)
        salt1 = os.urandom(TAMANHO_CHAVE)
        hash1 = os.urandom(TAMANHO_CHAVE)
        banco.cadastrar("eve", salt1, hash1)

        salt2 = os.urandom(TAMANHO_CHAVE)
        hash2 = os.urandom(TAMANHO_CHAVE)
        banco.cadastrar("eve", salt2, hash2)

        resultado = banco.buscar("eve")
        assert resultado["salt"] == salt2.hex()
        assert resultado["hash_chave"] == hash2.hex()

        os.unlink(caminho)

    def test_cria_diretorio_ao_salvar(self):
        """Cadastrar em diretório inexistente cria o diretório."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            caminho = os.path.join(tmp_dir, "sub", "novo", "user_db.json")
            banco = UserDB(caminho)
            salt = os.urandom(TAMANHO_CHAVE)
            hash_chave = os.urandom(TAMANHO_CHAVE)
            banco.cadastrar("frank", salt, hash_chave)

            assert os.path.exists(caminho)
            assert banco.buscar("frank") is not None
