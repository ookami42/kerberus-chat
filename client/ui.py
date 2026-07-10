"""Interface de terminal: login, envio/recebimento de mensagens.

Todas as interacoes de I/O do usuario (input, print, getpass)
ficam centralizadas aqui. O cliente de protocolo importa estas
funcoes sem se preocupar com a apresentacao visual.
"""

import getpass


def exibir_banner():
    """Mostra o cabecalho do programa."""
    print("\n" + "=" * 40)
    print("  KERBEROS NOTAS — Cliente")
    print("=" * 40)


def exibir_menu_principal() -> str:
    """Mostra o menu principal e retorna a opcao escolhida.

    Returns:
        str: Opcao digitada pelo usuario ("0", "1" ou "2").
    """
    print("  1. Cadastrar usuario")
    print("  2. Fazer login")
    print("  0. Sair")
    print()
    return input("Opcao: ").strip()


def perguntar_usuario() -> str:
    """Solicita o nome de usuario.

    Returns:
        str: Nome de usuario digitado.
    """
    return input("Usuario: ").strip()


def perguntar_senha() -> str:
    """Solicita a senha (oculta durante digitacao).

    Returns:
        str: Senha digitada.
    """
    return getpass.getpass("Senha: ")


def perguntar_conteudo() -> str:
    """Solicita o conteudo de uma nota para escrever.

    Returns:
        str: Texto digitado pelo usuario.
    """
    return input("Conteudo: ")


def mostrar_status(msg: str):
    """Exibe uma mensagem de sucesso.

    Args:
        msg: Texto descritivo do status.
    """
    print(f"[OK] {msg}")


def mostrar_erro(msg: str):
    """Exibe uma mensagem de erro.

    Args:
        msg: Texto descritivo do erro.
    """
    print(f"[ERRO] {msg}")


def mostrar_resultado(msg: str):
    """Exibe o resultado de uma operacao (ex.: conteudo de nota).

    Args:
        msg: Texto a ser exibido.
    """
    print(msg)


def exibir_ajuda():
    """Exibe a lista de comandos disponiveis no servico de notas."""
    print()
    print("Comandos:")
    print("  /notas                — listar suas notas")
    print("  /ler <arquivo>        — ler uma nota")
    print("  /escrever <arquivo>   — criar ou sobrescrever nota")
    print("  /deletar <arquivo>    — deletar uma nota")
    print("  /sair                 — encerrar")
    print()
