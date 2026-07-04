"""Testes unitários para scripts/cadastrar_usuario.py.

Testa a função main com IO injetada e caminho personalizável,
verificando o fluxo de cadastro de novo usuário e a detecção
de usuário já existente.
"""

import os
import tempfile

from common.config import TAMANHO_SALT
from common.crypto import derivar_chave
from as_server.user_db import UserDB
from scripts.cadastrar_usuario import main


def _caminho_tmp():
    """Gera um caminho temporário que não existe ainda."""
    tmp_dir = tempfile.mkdtemp()
    return os.path.join(tmp_dir, "test.json")


class TestCadastrarUsuario:
    """Testes do fluxo de cadastro com IO e caminho simulados."""

    def test_cadastro_novo_usuario(self):
        """Cadastro de usuário novo persiste no banco."""
        caminho = _caminho_tmp()
        main(
            perguntar_usuario=lambda p: "grace",
            perguntar_senha=lambda p: "minha_senha",
            caminho=caminho,
        )

        banco = UserDB(caminho)
        resultado = banco.buscar("grace")
        assert resultado is not None
        assert "salt" in resultado
        assert "hash_chave" in resultado

        os.unlink(caminho)

    def test_usuario_ja_existe_nao_sobrescreve(self):
        """Usuário existente não é sobrescrito."""
        caminho = _caminho_tmp()

        salt_original = os.urandom(TAMANHO_SALT)
        hash_original = os.urandom(TAMANHO_SALT)
        banco = UserDB(caminho)
        banco.cadastrar("heidi", salt_original, hash_original)

        main(
            perguntar_usuario=lambda p: "heidi",
            perguntar_senha=lambda p: "outra_senha",
            caminho=caminho,
        )

        banco2 = UserDB(caminho)
        resultado = banco2.buscar("heidi")
        assert resultado["salt"] == salt_original.hex()
        assert resultado["hash_chave"] == hash_original.hex()

        os.unlink(caminho)

    def test_salt_tem_tamanho_correto(self):
        """Salt gerado pelo cadastro tem TAMANHO_SALT bytes."""
        caminho = _caminho_tmp()
        main(
            perguntar_usuario=lambda p: "ivan",
            perguntar_senha=lambda p: "senha",
            caminho=caminho,
        )

        banco = UserDB(caminho)
        resultado = banco.buscar("ivan")
        salt_bytes = bytes.fromhex(resultado["salt"])
        assert len(salt_bytes) == TAMANHO_SALT

        os.unlink(caminho)

    def test_hash_e_pbkdf2_valido(self):
        """Hash armazenado é PBKDF2(senha, salt) válido."""
        caminho = _caminho_tmp()
        main(
            perguntar_usuario=lambda p: "judy",
            perguntar_senha=lambda p: "senha_judy",
            caminho=caminho,
        )

        banco = UserDB(caminho)
        resultado = banco.buscar("judy")
        salt_bytes = bytes.fromhex(resultado["salt"])
        hash_bytes = bytes.fromhex(resultado["hash_chave"])
        esperado = derivar_chave(b"senha_judy", salt_bytes)
        assert hash_bytes == esperado

        os.unlink(caminho)
