"""IaC: Terraform (bucket público, firewall aberto, criptografia desligada, banco público)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_code_iac import ids, lines_of, of, scan

from eigan.checks.code.iac_common import (
    BUCKET_PUBLIC,
    DB_PUBLIC,
    FIREWALL_OPEN,
    NO_ENCRYPTION,
)

PRIVATE_BUCKET = """resource "aws_s3_bucket" "dados" {
  bucket = "dados-privados"
}

resource "aws_s3_bucket_public_access_block" "dados" {
  bucket                  = aws_s3_bucket.dados.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


BARE_BUCKET = """resource "aws_s3_bucket" "dados" {
  bucket = "dados-privados"
}

"""


def sg(ingress: str) -> str:
    return f'resource "aws_security_group" "web" {{\n  name = "web"\n{ingress}}}\n'


def ingress(port: int, cidr: str = '"0.0.0.0/0"', *, to: int | None = None) -> str:
    return (
        "  ingress {\n"
        f"    from_port   = {port}\n"
        f"    to_port     = {to or port}\n"
        '    protocol    = "tcp"\n'
        f"    cidr_blocks = [{cidr}]\n"
        "  }\n"
    )


def tf(tmp_path: Path, text: str, name: str = "main.tf"):
    return scan(tmp_path, {name: text})


# -- S3 -------------------------------------------------------------------------------


def test_bucket_privado_com_bloqueio_nao_alerta(tmp_path: Path) -> None:
    assert not of(tf(tmp_path, PRIVATE_BUCKET), BUCKET_PUBLIC)


@pytest.mark.parametrize("acl", ["public-read", "public-read-write"])
def test_acl_publica_no_bucket(tmp_path: Path, acl: str) -> None:
    text = f'resource "aws_s3_bucket" "b" {{\n  bucket = "x"\n  acl    = "{acl}"\n}}\n'
    out = tf(tmp_path, text)
    assert of(out, BUCKET_PUBLIC)
    assert of(out, BUCKET_PUBLIC)[0].asset == "main.tf"
    assert lines_of(out, BUCKET_PUBLIC) == [3]


def test_acl_publica_em_recurso_separado(tmp_path: Path) -> None:
    text = (
        BARE_BUCKET
        + 'resource "aws_s3_bucket_acl" "a" {\n  bucket = aws_s3_bucket.dados.id\n'
        + '  acl    = "public-read"\n}\n'
    )
    assert of(tf(tmp_path, text), BUCKET_PUBLIC)


def test_acl_private_nao_alerta(tmp_path: Path) -> None:
    text = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl    = "private"\n}\n'
    assert not of(tf(tmp_path, text), BUCKET_PUBLIC)


def test_politica_com_principal_estrela(tmp_path: Path) -> None:
    text = (
        BARE_BUCKET
        + 'resource "aws_s3_bucket_policy" "p" {\n  bucket = aws_s3_bucket.dados.id\n'
        + '  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n'
        + '      Effect    = "Allow"\n      Principal = "*"\n      Action    = "s3:GetObject"\n'
        + '      Resource  = "arn:aws:s3:::dados-privados/*"\n    }]\n  })\n}\n'
    )
    assert of(tf(tmp_path, text), BUCKET_PUBLIC)


def test_politica_com_principal_especifico_nao_alerta(tmp_path: Path) -> None:
    text = (
        PRIVATE_BUCKET
        + 'resource "aws_s3_bucket_policy" "p" {\n  bucket = aws_s3_bucket.dados.id\n'
        + '  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n'
        + '      Effect    = "Allow"\n'
        + '      Principal = { AWS = "arn:aws:iam::123456789012:root" }\n'
        + '      Action    = "s3:GetObject"\n'
        + '      Resource  = "arn:aws:s3:::dados-privados/*"\n    }]\n  })\n}\n'
    )
    assert not of(tf(tmp_path, text), BUCKET_PUBLIC)


def test_bloqueio_de_acesso_publico_desligado(tmp_path: Path) -> None:
    text = PRIVATE_BUCKET.replace(
        "block_public_policy     = true", "block_public_policy     = false"
    )
    assert of(tf(tmp_path, text), BUCKET_PUBLIC)


# -- firewall -------------------------------------------------------------------------


@pytest.mark.parametrize("porta", [22, 3389, 5432, 3306, 6379, 27017, 1433])
def test_porta_sensivel_aberta_para_internet(tmp_path: Path, porta: int) -> None:
    out = tf(tmp_path, sg(ingress(porta)))
    assert of(out, FIREWALL_OPEN)


def test_porta_web_publica_nao_alerta(tmp_path: Path) -> None:
    out = tf(tmp_path, sg(ingress(443) + ingress(80)))
    assert not of(out, FIREWALL_OPEN)


def test_cidr_restrito_nao_alerta(tmp_path: Path) -> None:
    out = tf(tmp_path, sg(ingress(22, '"203.0.113.10/32"')))
    assert not of(out, FIREWALL_OPEN)


def test_cidr_privado_nao_alerta(tmp_path: Path) -> None:
    out = tf(tmp_path, sg(ingress(5432, '"10.0.0.0/16"')))
    assert not of(out, FIREWALL_OPEN)


def test_faixa_de_portas_que_inclui_ssh(tmp_path: Path) -> None:
    out = tf(tmp_path, sg(ingress(0, to=65535)))
    assert of(out, FIREWALL_OPEN)


def test_regra_ipv6_aberta(tmp_path: Path) -> None:
    text = (
        'resource "aws_security_group" "w" {\n  ingress {\n    from_port = 22\n'
        '    to_port = 22\n    protocol = "tcp"\n    ipv6_cidr_blocks = ["::/0"]\n  }\n}\n'
    )
    assert of(tf(tmp_path, text), FIREWALL_OPEN)


def test_regra_separada_security_group_rule(tmp_path: Path) -> None:
    text = (
        'resource "aws_security_group_rule" "ssh" {\n  type = "ingress"\n  from_port = 22\n'
        '  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n'
        "  security_group_id = aws_security_group.w.id\n}\n"
    )
    assert of(tf(tmp_path, text), FIREWALL_OPEN)


def test_regra_de_saida_aberta_nao_alerta(tmp_path: Path) -> None:
    text = (
        'resource "aws_security_group_rule" "out" {\n  type = "egress"\n  from_port = 22\n'
        '  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n'
        "  security_group_id = aws_security_group.w.id\n}\n"
    )
    assert not of(tf(tmp_path, text), FIREWALL_OPEN)


def test_azure_regra_aberta(tmp_path: Path) -> None:
    text = (
        'resource "azurerm_network_security_rule" "rdp" {\n  name = "rdp"\n'
        '  direction = "Inbound"\n  access = "Allow"\n  protocol = "Tcp"\n'
        '  destination_port_range = "3389"\n  source_address_prefix = "*"\n}\n'
    )
    assert of(tf(tmp_path, text), FIREWALL_OPEN)


def test_google_firewall_aberto(tmp_path: Path) -> None:
    text = (
        'resource "google_compute_firewall" "ssh" {\n  name = "ssh"\n  network = "default"\n'
        '  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n'
        '    ports    = ["22"]\n  }\n}\n'
    )
    assert of(tf(tmp_path, text), FIREWALL_OPEN)


# -- criptografia e banco público -----------------------------------------------------


def test_rds_sem_storage_encrypted_e_false_por_padrao(tmp_path: Path) -> None:
    text = 'resource "aws_db_instance" "d" {\n  engine = "postgres"\n}\n'
    assert of(tf(tmp_path, text), NO_ENCRYPTION)


def test_rds_com_criptografia_nao_alerta(tmp_path: Path) -> None:
    text = (
        'resource "aws_db_instance" "d" {\n  engine = "postgres"\n  storage_encrypted = true\n}\n'
    )
    assert not of(tf(tmp_path, text), NO_ENCRYPTION)


def test_rds_restaurado_de_snapshot_nao_e_acusado_por_ausencia(tmp_path: Path) -> None:
    text = (
        'resource "aws_db_instance" "d" {\n  snapshot_identifier = "snap-1"\n'
        '  engine = "postgres"\n}\n'
    )
    assert not of(tf(tmp_path, text), NO_ENCRYPTION)


def test_ebs_so_alerta_com_false_explicito(tmp_path: Path) -> None:
    ausente = tf(tmp_path, 'resource "aws_ebs_volume" "v" {\n  size = 10\n}\n')
    falso = scan(
        tmp_path / "b",
        {"main.tf": 'resource "aws_ebs_volume" "v" {\n  size = 10\n  encrypted = false\n}\n'},
    )
    assert not of(ausente, NO_ENCRYPTION)
    assert of(falso, NO_ENCRYPTION)
    assert lines_of(falso, NO_ENCRYPTION) == [3]


def test_banco_publicamente_acessivel(tmp_path: Path) -> None:
    base = 'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n'
    publico = tf(tmp_path, base + "  publicly_accessible = true\n}\n")
    privado = scan(tmp_path / "b", {"main.tf": base + "  publicly_accessible = false\n}\n"})
    assert of(publico, DB_PUBLIC)
    assert not of(privado, DB_PUBLIC)


# -- parser tolerante -----------------------------------------------------------------


def test_comentarios_e_heredoc_nao_confundem_o_parser(tmp_path: Path) -> None:
    text = (
        '# acl = "public-read"\n// publicly_accessible = true\n/* storage_encrypted = false */\n'
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  tags = {\n    nota = <<EOT\n'
        '  acl = "public-read"\n  cidr_blocks = ["0.0.0.0/0"]\nEOT\n  }\n}\n'
    )
    assert not tf(tmp_path, text).findings


def test_arquivo_tf_invalido_nao_derruba_a_checagem(tmp_path: Path) -> None:
    out = tf(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = \n  ]]] {{{\n')
    assert isinstance(ids(out), set)


def test_variavel_com_default_publico(tmp_path: Path) -> None:
    text = 'variable "cidr" {\n  default = "0.0.0.0/0"\n}\n' + sg(
        "  ingress {\n    from_port = 22\n    to_port = 22\n"
        '    protocol = "tcp"\n    cidr_blocks = [var.cidr]\n  }\n'
    )
    assert of(tf(tmp_path, text), FIREWALL_OPEN)


def test_modulo_resolve_variavel_entre_arquivos_da_mesma_pasta(tmp_path: Path) -> None:
    out = scan(
        tmp_path,
        {
            "infra/variables.tf": 'variable "cidr" {\n  default = "0.0.0.0/0"\n}\n',
            "infra/main.tf": sg(
                "  ingress {\n    from_port = 22\n    to_port = 22\n"
                '    protocol = "tcp"\n    cidr_blocks = [var.cidr]\n  }\n'
            ),
        },
    )
    found = of(out, FIREWALL_OPEN)
    assert found
    assert found[0].asset == "infra/main.tf"


def test_arquivo_tfvars_e_ignorado(tmp_path: Path) -> None:
    out = scan(tmp_path, {"prod.tfvars": 'acl = "public-read"\n'})
    assert ids(out) == set()


def test_correcao_presente(tmp_path: Path) -> None:
    out = tf(tmp_path, sg(ingress(22)))
    assert out.findings
    for f in out.findings:
        assert f.details["correcao"].strip()
        assert f.details["tipo"] == "Terraform"


# -- regressões da revisão ----------------------------------------------------------------------


def _azure(protocol: str, port: str) -> str:
    return (
        'resource "azurerm_network_security_rule" "r" {\n  name = "r"\n'
        f'  direction = "Inbound"\n  access = "Allow"\n  protocol = "{protocol}"\n'
        f'  destination_port_range = "{port}"\n  source_address_prefix = "*"\n}}\n'
    )


def test_azure_protocolo_asterisco_com_porta_web_nao_alerta(tmp_path: Path) -> None:
    assert not of(tf(tmp_path, _azure("*", "443")), FIREWALL_OPEN)


def test_azure_protocolo_asterisco_rdp_nomeia_a_porta(tmp_path: Path) -> None:
    achados = of(tf(tmp_path, _azure("*", "3389")), FIREWALL_OPEN)
    assert achados
    assert "todas as portas" not in achados[0].title
    assert "3389" in achados[0].title


def test_recurso_com_count_zero_e_ignorado(tmp_path: Path) -> None:
    text = (
        'resource "aws_security_group_rule" "y" {\n  count = 0\n  type = "ingress"\n'
        '  protocol = "tcp"\n  from_port = 22\n  to_port = 22\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n}\n'
    )
    assert not of(tf(tmp_path, text), FIREWALL_OPEN)
    assert of(tf(tmp_path, text.replace("  count = 0\n", "")), FIREWALL_OPEN)


def test_regras_ipv4_e_ipv6_do_mesmo_grupo_nao_se_fundem(tmp_path: Path) -> None:
    text = (
        'resource "aws_security_group" "web" {\n  name = "web"\n'
        '  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
        '  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
        '    ipv6_cidr_blocks = ["::/0"]\n  }\n}\n'
    )
    assert len(of(tf(tmp_path, text), FIREWALL_OPEN)) == 2
