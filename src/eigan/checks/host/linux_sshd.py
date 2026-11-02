"""Configuração efetiva do servidor OpenSSH (sshd), só leitura.

Com root, o próprio sshd calcula a configuração global (``sshd -T``). Sem root, ou se
o ``sshd -T`` falhar, lemos ``/etc/ssh/sshd_config`` seguindo as regras do
sshd_config(5):

- vale a PRIMEIRA ocorrência de cada palavra-chave (o contrário da maioria dos
  arquivos de configuração);
- ``Include`` é processado no ponto em que aparece, com curingas expandidos em ordem
  léxica; caminho relativo fica em ``/etc/ssh``;
- blocos ``Match`` são condicionais e ficam de fora da seção global, exceto
  ``Match all``, que vale para todas as conexões e por isso sobrepõe a seção global;
- um ``Match`` dentro de um arquivo incluído termina no fim desse arquivo (o sshd
  restaura o estado do arquivo que fez o Include).

Arquivo incluído que não pôde ser lido deixa uma lacuna: o que vem depois dele (e os
valores padrão) pode ter sido definido lá, então esses valores ficam "incertos".
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from .linux_sistema import SistemaLinux
from .sistema import AcessoNegado

ARQUIVO = "/etc/ssh/sshd_config"
PASTA = "/etc/ssh"
#: limite de segurança contra Include recursivo
PROFUNDIDADE_MAXIMA = 16
#: limite de arquivos lidos numa mesma configuração
MAXIMO_ARQUIVOS = 256
#: onde algumas distribuições (ex.: openSUSE) guardam o arquivo do fabricante
ARQUIVO_FABRICANTE = "/usr/etc/ssh/sshd_config"
#: padrões do OpenSSH (sshd_config(5)) para as opções avaliadas
PADROES = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "usepam": "no",
    "kbdinteractiveauthentication": "yes",
    "authenticationmethods": "any",
}

_LINHA = re.compile(r"^\s*([^\s=#]+)(?:\s*=\s*|\s+|$)(.*)$")
_ARGUMENTO = re.compile(r'"([^"]*)"|(\S+)')


@dataclass(frozen=True)
class Valor:
    valor: str
    origem: str  # "arquivo:linha", "sshd -T" ou "padrão do OpenSSH"
    certo: bool = True  # False quando um arquivo ilegível pode ter definido antes


@dataclass
class ConfigSshd:
    fonte: str  # "sshd -T" | "arquivos"
    valores: dict[str, Valor] = field(default_factory=dict)
    todos: dict[str, Valor] = field(default_factory=dict)  # blocos "Match all" (já em valores)
    arquivos: list[str] = field(default_factory=list)
    condicionais: list[str] = field(default_factory=list)  # blocos Match ignorados
    ilegiveis: list[str] = field(default_factory=list)

    def efetivo(self, chave: str) -> Valor:
        """Valor que vale para todas as conexões (ou o padrão do OpenSSH)."""
        nome = chave.lower()
        valor = self.valores.get(nome)
        if valor is not None:
            return valor
        return Valor(PADROES.get(nome, ""), "padrão do OpenSSH", certo=not self.ilegiveis)


def tokens(linha: str) -> list[str]:
    """Palavra-chave e argumentos (aspas duplas, ``Chave=valor``, ``#`` inicia comentário)."""
    texto = linha.strip()
    if not texto or texto.startswith("#"):
        return []
    achado = _LINHA.match(texto)
    if achado is None:
        return []
    partes = [achado.group(1)]
    for argumento in _ARGUMENTO.finditer(achado.group(2)):
        if argumento.group(1) is not None:
            partes.append(argumento.group(1))
        elif argumento.group(2).startswith("#"):
            break
        else:
            partes.append(argumento.group(2))
    return partes


def _absoluto(caminho: str) -> str:
    return caminho if caminho.startswith("/") else posixpath.join(PASTA, caminho)


class _Leitor:
    """Percorre o sshd_config e os Include na ordem em que o sshd os processa."""

    def __init__(self, sis: SistemaLinux) -> None:
        self.sis = sis
        self.globais: dict[str, Valor] = {}
        self.todos: dict[str, Valor] = {}  # blocos "Match all"
        self.cadeia: list[str] = []  # arquivos em processamento (evita Include circular)
        self.lidos = 0
        self.config = ConfigSshd("arquivos")

    def processar(self, caminho: str, bloco: str, profundidade: int) -> None:
        if caminho in self.cadeia or self.lidos >= MAXIMO_ARQUIVOS:
            return  # Include circular ou fora de proporção: o sshd real recusaria
        self.lidos += 1
        texto = self.sis.ler(caminho)
        if texto is None:
            return
        self.cadeia.append(caminho)
        try:
            self._linhas(caminho, texto, bloco, profundidade)
        finally:
            self.cadeia.pop()

    def _linhas(self, caminho: str, texto: str, bloco: str, profundidade: int) -> None:
        self.config.arquivos.append(caminho)
        # incluído de dentro de um Match condicional: nem um "Match all" dele vale sempre
        nunca = bloco == "condicional"
        for numero, linha in enumerate(texto.splitlines(), start=1):
            partes = tokens(linha)
            if not partes:
                continue
            chave, argumentos = partes[0].lower(), partes[1:]
            if chave == "match":
                todos = [a.lower() for a in argumentos] == ["all"]
                bloco = "todos" if todos and not nunca else "condicional"
                if bloco == "condicional":
                    self.config.condicionais.append(f"{caminho}:{numero}")
            elif chave == "include":
                self._incluir(argumentos, bloco, profundidade)
            elif argumentos and bloco != "condicional":
                destino = self.globais if bloco == "global" else self.todos
                certo = not self.config.ilegiveis
                destino.setdefault(chave, Valor(argumentos[0], f"{caminho}:{numero}", certo))

    def _incluir(self, padroes: list[str], bloco: str, profundidade: int) -> None:
        if profundidade >= PROFUNDIDADE_MAXIMA:
            return
        for padrao in padroes:
            try:
                arquivos = self.sis.expandir(_absoluto(padrao))
            except AcessoNegado:
                self.config.ilegiveis.append(_absoluto(padrao))
                continue
            for arquivo in arquivos:
                try:
                    self.processar(arquivo, bloco, profundidade + 1)
                except AcessoNegado:
                    self.config.ilegiveis.append(arquivo)

    def resultado(self) -> ConfigSshd:
        self.config.todos = dict(self.todos)
        self.config.valores = {**self.globais, **self.todos}
        return self.config


def ler_arquivos(sis: SistemaLinux) -> ConfigSshd | None:
    """Configuração lida dos arquivos; None se não há sshd_config.

    Levanta :class:`AcessoNegado` se o próprio sshd_config não pode ser lido.
    """
    arquivo = ARQUIVO
    if sis.ler(arquivo) is None:
        arquivo = ARQUIVO_FABRICANTE
        if sis.ler(arquivo) is None:
            return None
    leitor = _Leitor(sis)
    leitor.processar(arquivo, "global", 0)
    return leitor.resultado()


def ler_sshd_t(sis: SistemaLinux) -> dict[str, str] | None:
    """Saída do ``sshd -T`` (só com root): palavra-chave em minúsculas -> valor."""
    resultado = sis.comando("sshd", "-T", tempo=20.0)
    if resultado is None or resultado.codigo != 0:
        return None
    valores: dict[str, str] = {}
    for linha in resultado.saida.splitlines():
        chave, _, valor = linha.strip().partition(" ")
        if chave and valor:
            valores.setdefault(chave.lower(), valor.strip())
    return valores if "permitrootlogin" in valores else None


def configuracao(sis: SistemaLinux) -> ConfigSshd | None:
    """Configuração efetiva: ``sshd -T`` quando há root, senão a leitura dos arquivos."""
    arquivos: ConfigSshd | None = None
    try:
        arquivos = ler_arquivos(sis)
    except AcessoNegado:
        if not sis.root():
            raise
    calculado = ler_sshd_t(sis) if sis.root() else None
    if calculado is None:
        return arquivos
    config = ConfigSshd("sshd -T")
    for chave, valor in calculado.items():
        lido = arquivos.valores.get(chave) if arquivos is not None else None
        mesmo = lido is not None and lido.valor.lower() == valor.lower()
        config.valores[chave] = Valor(
            valor, lido.origem if lido is not None and mesmo else "sshd -T"
        )
    if arquivos is not None:
        config.arquivos, config.condicionais = arquivos.arquivos, arquivos.condicionais
        # "Match all" vale para todas as conexões: garante o mesmo resultado em qualquer versão
        config.todos = dict(arquivos.todos)
        config.valores.update(arquivos.todos)
    return config
