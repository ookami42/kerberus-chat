"""Testes unitários para common/crypto.py.

Testa as primitivas criptográficas: cifragem/decifragem AES-GCM
e derivação de chave com PBKDF2. Cada teste verifica um comportamento
específico descrito nas issues #2, #3 e #4.
"""

import os
import pytest
from cryptography.exceptions import InvalidTag

from common.crypto import cifrar_aes_gcm, decifrar_aes_gcm, derivar_chave
from common.config import TAMANHO_CHAVE


class TestCifrarAesGcm:
    """Testes da função de cifragem AES-GCM (issue #2)."""

    def test_saida_tem_tamanho_correto(self):
        """Cifrar 5 bytes deve retornar nonce(12) + ciphertext(5) + tag(16) = 33 bytes.

        O nonce tem 12 bytes. O ciphertext do AES-GCM tem o mesmo tamanho dos dados
        de entrada. A tag de autenticação tem 16 bytes e já vem embutida no retorno.
        """
        chave = os.urandom(TAMANHO_CHAVE)
        resultado = cifrar_aes_gcm(chave, b"teste")
        # nonce(12) + ciphertext(5) + tag(16) = 33
        assert len(resultado) == 12 + 5 + 16

    def test_saida_vazia_retorna_28_bytes(self):
        """Cifrar dados vazios retorna nonce(12) + tag(16) = 28 bytes."""
        chave = os.urandom(TAMANHO_CHAVE)
        resultado = cifrar_aes_gcm(chave, b"")
        assert len(resultado) == 12 + 0 + 16

    def test_nonces_sao_diferentes(self):
        """Duas cifragens com os mesmos dados devem gerar nonces diferentes.

        Isso é essencial para a segurança: mesmo que um atacante veja duas
        cifragens dos mesmos dados, os nonces diferentes impedem análise
        de padrões.
        """
        chave = os.urandom(TAMANHO_CHAVE)
        dados = b"mensagem identica"
        resultado1 = cifrar_aes_gcm(chave, dados)
        resultado2 = cifrar_aes_gcm(chave, dados)
        # Os primeiros 12 bytes (nonce) devem ser diferentes
        assert resultado1[:12] != resultado2[:12]

    def test_resultados_sao_diferentes(self):
        """Duas cifragens idênticas produzem resultados completamente diferentes."""
        chave = os.urandom(TAMANHO_CHAVE)
        dados = b"teste"
        resultado1 = cifrar_aes_gcm(chave, dados)
        resultado2 = cifrar_aes_gcm(chave, dados)
        assert resultado1 != resultado2


class TestDecifrarAesGcm:
    """Testes da função de decifragem AES-GCM (issue #3)."""

    def test_roundtrip_retorna_dados_originais(self):
        """Decifrar o que foi cifrado deve retornar os dados originais."""
        chave = os.urandom(TAMANHO_CHAVE)
        dados = b"dados secretos"
        cifrado = cifrar_aes_gcm(chave, dados)
        decifrado = decifrar_aes_gcm(chave, cifrado)
        assert decifrado == dados

    def test_roundtrip_com_dados_vazios(self):
        """Roundtrip com dados vazios funciona corretamente."""
        chave = os.urandom(TAMANHO_CHAVE)
        cifrado = cifrar_aes_gcm(chave, b"")
        decifrado = decifrar_aes_gcm(chave, cifrado)
        assert decifrado == b""

    def test_roundtrip_com_dados_grandes(self):
        """Roundtrip com 1KB de dados funciona corretamente."""
        chave = os.urandom(TAMANHO_CHAVE)
        dados = os.urandom(1024)
        cifrado = cifrar_aes_gcm(chave, dados)
        decifrado = decifrar_aes_gcm(chave, cifrado)
        assert decifrado == dados

    def test_chave_errada_raises_invalid_tag(self):
        """Decifrar com chave errada lança InvalidTag.

        Se alguém tentar decifrar uma mensagem com a chave incorreta,
        o AES-GCM detecta a violação e lança exceção. Isso protege
        contra ataques de chave errada.
        """
        chave_correta = os.urandom(TAMANHO_CHAVE)
        chave_errada = os.urandom(TAMANHO_CHAVE)
        cifrado = cifrar_aes_gcm(chave_correta, b"secreto")
        with pytest.raises(InvalidTag):
            decifrar_aes_gcm(chave_errada, cifrado)

    def test_dados_violados_raises_invalid_tag(self):
        """Alterar 1 byte do ciphertext deve falhar na decifragem.

        O AES-GCM possui tag de autenticação que detecta qualquer
        alteração nos dados cifrados. Mesmo 1 byte alterado causa falha.
        """
        chave = os.urandom(TAMANHO_CHAVE)
        cifrado = bytearray(cifrar_aes_gcm(chave, b"teste"))
        # Altera 1 byte no ciphertext (posição 12, após o nonce)
        cifrado[12] ^= 0xFF
        with pytest.raises(InvalidTag):
            decifrar_aes_gcm(chave, bytes(cifrado))

    def test_tres_mensagens_diferentes_funcionam(self):
        """Verifica roundtrip com 3 mensagens distintas.

        Garante que a função funciona para diferentes valores de entrada,
        não apenas para um caso específico.
        """
        chave = os.urandom(TAMANHO_CHAVE)
        mensagens = [b"primeira", b"segunda mensagem", b"terceira!"]
        for msg in mensagens:
            cifrado = cifrar_aes_gcm(chave, msg)
            decifrado = decifrar_aes_gcm(chave, cifrado)
            assert decifrado == msg


class TestDerivarChave:
    """Testes da função de derivação de chave PBKDF2 (issue #4)."""

    def test_retorna_16_bytes(self):
        """Derivar chave deve retornar exatamente 16 bytes (128 bits)."""
        senha = b"minha_senha"
        salt = os.urandom(TAMANHO_CHAVE)
        chave = derivar_chave(senha, salt)
        assert len(chave) == TAMANHO_CHAVE

    def test_mesma_senha_mesmo_salt_retorna_mesmo_resultado(self):
        """PBKDF2 é determinístico: mesma entrada → mesma saída."""
        senha = b"senha_secreta"
        salt = os.urandom(TAMANHO_CHAVE)
        chave1 = derivar_chave(senha, salt)
        chave2 = derivar_chave(senha, salt)
        assert chave1 == chave2

    def test_salt_diferente_retorna_resultado_diferente(self):
        """Salt diferente produz chave diferente.

        O salt garante que mesmo senhas iguais gerem chaves diferentes
        em contextos diferentes, prevenindo ataques de rainbow table.
        """
        senha = b"mesma_senha"
        salt1 = os.urandom(TAMANHO_CHAVE)
        salt2 = os.urandom(TAMANHO_CHAVE)
        chave1 = derivar_chave(senha, salt1)
        chave2 = derivar_chave(senha, salt2)
        assert chave1 != chave2

    def test_senha_diferente_retorna_resultado_diferente(self):
        """Senhas diferentes produzem chaves diferentes."""
        salt = os.urandom(TAMANHO_CHAVE)
        chave1 = derivar_chave(b"senha_a", salt)
        chave2 = derivar_chave(b"senha_b", salt)
        assert chave1 != chave2

