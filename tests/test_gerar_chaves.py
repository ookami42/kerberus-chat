"""Testes unitários para scripts/gerar_chaves.py.

Testa a geração das chaves mestras: criação do diretório, tamanho
dos arquivos, conteúdo diferente entre si e entre execuções (issue #8).
"""

import os
import tempfile

from common.config import TAMANHO_CHAVE, AS_MASTER_KEY_PATH, SVC_MASTER_KEY_PATH
from scripts.gerar_chaves import gerar_chaves

_NOMES_CHAVES = (os.path.basename(AS_MASTER_KEY_PATH), os.path.basename(SVC_MASTER_KEY_PATH))


class TestGerarChaves:
    """Testes da função de geração de chaves mestras."""

    def test_cria_diretorio_keys(self):
        """Diretório de chaves é criado se não existir."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            keys_dir = os.path.join(tmp_dir, "sub", "keys")
            gerar_chaves(keys_dir)
            assert os.path.isdir(keys_dir)

    def test_cria_dois_arquivos(self):
        """Gera exatamente os 2 arquivos de chave."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            gerar_chaves(tmp_dir)
            for nome in _NOMES_CHAVES:
                caminho = os.path.join(tmp_dir, nome)
                assert os.path.isfile(caminho), f"Arquivo {nome} não foi criado"

    def test_cada_arquivo_tem_tamanho_correto(self):
        """Cada arquivo de chave tem exatamente TAMANHO_CHAVE bytes."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            gerar_chaves(tmp_dir)
            for nome in _NOMES_CHAVES:
                caminho = os.path.join(tmp_dir, nome)
                tamanho = os.path.getsize(caminho)
                assert tamanho == TAMANHO_CHAVE, f"{nome} tem {tamanho} bytes, esperado {TAMANHO_CHAVE}"

    def test_arquivos_sao_diferentes(self):
        """As chaves geradas têm conteúdo diferente entre si."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            gerar_chaves(tmp_dir)
            conteudos = []
            for nome in _NOMES_CHAVES:
                caminho = os.path.join(tmp_dir, nome)
                with open(caminho, "rb") as f:
                    conteudos.append(f.read())
            assert len(set(conteudos)) == len(_NOMES_CHAVES), "Há chaves duplicadas"

    def test_sobrescreve_arquivos_existentes(self):
        """Executar duas vezes mantém os arquivos de tamanho correto."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            gerar_chaves(tmp_dir)
            gerar_chaves(tmp_dir)
            for nome in _NOMES_CHAVES:
                caminho = os.path.join(tmp_dir, nome)
                assert os.path.isfile(caminho)
                assert os.path.getsize(caminho) == TAMANHO_CHAVE

    def test_chaves_sao_diferentes_entre_execucoes(self):
        """Duas execuções geram chaves com conteúdo diferente."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            gerar_chaves(tmp_dir)
            primeira_rodada = {}
            for nome in _NOMES_CHAVES:
                caminho = os.path.join(tmp_dir, nome)
                with open(caminho, "rb") as f:
                    primeira_rodada[nome] = f.read()

            gerar_chaves(tmp_dir)
            for nome in _NOMES_CHAVES:
                caminho = os.path.join(tmp_dir, nome)
                with open(caminho, "rb") as f:
                    conteudo = f.read()
                assert (
                    conteudo != primeira_rodada[nome]
                ), f"{nome} foi igual à execução anterior"
