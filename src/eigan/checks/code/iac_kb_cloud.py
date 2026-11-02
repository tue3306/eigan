"""Base de conhecimento dos achados de nuvem encontrados em arquivos Terraform."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity
from .iac_common import BUCKET_PUBLIC, DB_PUBLIC, FIREWALL_OPEN, NO_ENCRYPTION

_S3_BPA = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
)
_S3_ACL = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"
_TF_AWS = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
_TF_AZURE = "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/"
_TF_GOOGLE = "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/"


def _terraform(code: str, label: str = "Terraform") -> Fix:
    return Fix("terraform", label, code, "hcl")


kb.register(
    KBEntry(
        id=BUCKET_PUBLIC,
        title="Armazenamento de arquivos público na nuvem",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary=(
            "O Terraform deixa um bucket ou container de armazenamento acessível por qualquer "
            "pessoa ou por qualquer conta da nuvem."
        ),
        explanation=(
            "No Amazon S3, uma ACL é pública quando concede qualquer permissão aos grupos AllUsers "
            "(qualquer pessoa no mundo) ou AuthenticatedUsers (qualquer conta da AWS, não só a sua). "
            "Uma política de bucket é pública quando libera 'Principal: *' sem uma condição com valor "
            "fixo (como aws:SourceVpc ou aws:SourceIp). No Azure, o nível de acesso 'blob' ou "
            "'container' dispensa autenticação; no Google Cloud, os membros allUsers e "
            "allAuthenticatedUsers fazem o mesmo. O bloqueio de acesso público do S3, quando "
            "desligado, deixa de impedir esses erros."
        ),
        risk=(
            "Vazamento de todos os arquivos do bucket (backups, documentos, dados pessoais). Com "
            "permissão de escrita, qualquer pessoa também pode gravar arquivos: adulterar conteúdo, "
            "publicar malware no seu domínio e gerar custo na sua conta."
        ),
        steps=(
            "Confirme se o bucket precisa mesmo ser público (site estático, por exemplo). Se não, "
            "remova a ACL pública ou a instrução 'Principal: *' da política.",
            "Ative os quatro controles de bloqueio de acesso público do S3 no bucket e, de "
            "preferência, na conta.",
            "Para distribuir arquivos, use CDN com acesso restrito à origem ou URLs assinadas.",
            "Se dados pessoais ficaram expostos, avalie o incidente e as obrigações da LGPD.",
        ),
        examples=(
            _terraform(
                'resource "aws_s3_bucket_public_access_block" "dados" {\n'
                "  bucket                  = aws_s3_bucket.dados.id\n"
                "  block_public_acls       = true\n"
                "  block_public_policy     = true\n"
                "  ignore_public_acls      = true\n"
                "  restrict_public_buckets = true\n"
                "}",
                "Terraform (AWS S3)",
            ),
            _terraform(
                'data "aws_iam_policy_document" "leitura_interna" {\n'
                "  statement {\n"
                '    actions   = ["s3:GetObject"]\n'
                '    resources = ["${aws_s3_bucket.dados.arn}/*"]\n'
                "    principals {\n"
                '      type        = "AWS"\n'
                "      identifiers = [aws_iam_role.app.arn]\n"
                "    }\n"
                "  }\n"
                "}",
                "Terraform (política sem acesso público)",
            ),
            _terraform(
                'resource "azurerm_storage_container" "dados" {\n'
                '  name                  = "dados"\n'
                '  container_access_type = "private"\n'
                "}",
                "Terraform (Azure)",
            ),
            _terraform(
                'resource "google_storage_bucket_iam_member" "leitura" {\n'
                "  bucket = google_storage_bucket.dados.name\n"
                '  role   = "roles/storage.objectViewer"\n'
                '  member = "serviceAccount:app@meu-projeto.iam.gserviceaccount.com"\n'
                "}",
                "Terraform (Google Cloud)",
            ),
        ),
        verify=(
            "Depois do 'terraform apply', tente abrir um arquivo do bucket sem credenciais: a resposta "
            "deve ser 'AccessDenied'. Rode o EIGAN de novo."
        ),
        effort="medio",
        fix_group="iac",
        references=(
            _S3_BPA,
            _S3_ACL,
            _TF_AWS + "s3_bucket_public_access_block",
            _TF_AZURE + "storage_container",
            _TF_GOOGLE + "storage_bucket_iam",
            "https://cwe.mitre.org/data/definitions/732.html",
        ),
        cwe="CWE-732",
        owasp="A01:2021",
        cis=("3.3",),
        lgpd=True,
        tags=("nuvem", "terraform", "armazenamento"),
    ),
    KBEntry(
        id=FIREWALL_OPEN,
        title="Firewall da nuvem aberto para a Internet em porta sensível",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary=(
            "Uma regra de entrada libera acesso remoto ou a banco de dados para qualquer endereço "
            "(0.0.0.0/0 ou ::/0)."
        ),
        explanation=(
            "Security groups (AWS), Network Security Groups (Azure) e regras de firewall (Google "
            "Cloud) decidem quem alcança cada porta. A origem 0.0.0.0/0 (ou ::/0, em IPv6) significa "
            "'qualquer endereço da Internet'. Em portas de administração (SSH, RDP) e de bancos de "
            "dados, isso coloca o serviço ao alcance de robôs que varrem a Internet o tempo todo."
        ),
        risk=(
            "Tentativas contínuas de adivinhar senhas e exploração de falhas conhecidas do serviço. "
            "Uma senha fraca ou uma versão desatualizada bastam para perder o servidor ou os dados."
        ),
        steps=(
            "Troque a origem pela faixa de endereços da VPN ou do escritório, ou pelo security group "
            "da aplicação que precisa do acesso.",
            "Para administração, prefira acesso sem porta aberta (AWS Systems Manager, Azure Bastion, "
            "Identity-Aware Proxy do Google) ou uma VPN.",
            "Bancos de dados não devem ter nenhuma regra vinda da Internet: libere só a rede interna.",
        ),
        examples=(
            _terraform(
                'resource "aws_vpc_security_group_ingress_rule" "ssh_admin" {\n'
                "  security_group_id = aws_security_group.web.id\n"
                '  cidr_ipv4         = "10.20.0.0/24"   # rede da VPN\n'
                "  from_port         = 22\n"
                "  to_port           = 22\n"
                '  ip_protocol       = "tcp"\n'
                "}",
                "Terraform (AWS)",
            ),
            _terraform(
                'resource "azurerm_network_security_rule" "ssh_admin" {\n'
                '  name                        = "ssh-admin"\n'
                "  priority                    = 100\n"
                '  direction                   = "Inbound"\n'
                '  access                      = "Allow"\n'
                '  protocol                    = "Tcp"\n'
                '  source_port_range           = "*"\n'
                '  destination_port_range      = "22"\n'
                '  source_address_prefix       = "10.20.0.0/24"\n'
                '  destination_address_prefix  = "*"\n'
                "  resource_group_name         = azurerm_resource_group.main.name\n"
                "  network_security_group_name = azurerm_network_security_group.main.name\n"
                "}",
                "Terraform (Azure)",
            ),
            _terraform(
                'resource "google_compute_firewall" "ssh_admin" {\n'
                '  name          = "ssh-admin"\n'
                "  network       = google_compute_network.main.name\n"
                '  source_ranges = ["10.20.0.0/24"]\n'
                "  allow {\n"
                '    protocol = "tcp"\n'
                '    ports    = ["22"]\n'
                "  }\n"
                "}",
                "Terraform (Google Cloud)",
            ),
        ),
        verify=(
            "Depois do 'terraform apply', um teste de conexão a partir de fora da rede permitida "
            "(ex.: 'nc -vz <ip> 22') deve falhar. Rode o EIGAN de novo."
        ),
        effort="baixo",
        fix_group="iac",
        references=(
            "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
            _TF_AWS + "vpc_security_group_ingress_rule",
            _TF_AZURE + "network_security_rule",
            _TF_GOOGLE + "compute_firewall",
            "https://cwe.mitre.org/data/definitions/284.html",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.4", "12.2"),
        tags=("nuvem", "terraform", "rede"),
    ),
    KBEntry(
        id=NO_ENCRYPTION,
        title="Criptografia desligada em recurso de nuvem",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary="Um disco, banco de dados ou cache é criado sem criptografia dos dados.",
        explanation=(
            "Criptografia em repouso protege os dados caso um disco, snapshot ou backup caia em mãos "
            "erradas; criptografia em trânsito protege o tráfego na rede. Em alguns recursos, como "
            "aws_db_instance, o padrão do Terraform é 'false': sem o argumento, o banco nasce sem "
            "criptografia. E ligar depois costuma exigir recriar o recurso ou restaurar uma cópia."
        ),
        risk=(
            "Snapshots copiados, discos reaproveitados ou tráfego interceptado expõem os dados em "
            "texto puro. Em dados pessoais, isso pesa na avaliação de um incidente segundo a LGPD."
        ),
        steps=(
            "Defina o argumento de criptografia como true (storage_encrypted, encrypted, "
            "at_rest_encryption_enabled, transit_encryption_enabled).",
            "Em recursos que já existem, veja se a mudança recria o recurso: planeje a janela e "
            "migre a partir de um snapshot criptografado.",
            "Considere usar uma chave própria do KMS para controlar quem pode decifrar.",
        ),
        examples=(
            _terraform(
                'resource "aws_db_instance" "principal" {\n'
                '  identifier        = "principal"\n'
                '  engine            = "postgres"\n'
                '  instance_class    = "db.t3.micro"\n'
                "  allocated_storage = 20\n"
                "  storage_encrypted = true\n"
                "  kms_key_id        = aws_kms_key.dados.arn\n"
                "}",
                "Terraform (RDS)",
            ),
            _terraform(
                'resource "aws_ebs_volume" "dados" {\n'
                '  availability_zone = "sa-east-1a"\n'
                "  size              = 40\n"
                "  encrypted         = true\n"
                "}",
                "Terraform (EBS)",
            ),
            _terraform(
                'resource "aws_elasticache_replication_group" "cache" {\n'
                '  replication_group_id       = "cache"\n'
                '  description                = "cache da aplicação"\n'
                "  at_rest_encryption_enabled = true\n"
                "  transit_encryption_enabled = true\n"
                "}",
                "Terraform (ElastiCache)",
            ),
        ),
        verify=(
            "'terraform plan' não deve mostrar mudanças depois de aplicar e o console da nuvem deve "
            "indicar o recurso como criptografado. Rode o EIGAN de novo."
        ),
        effort="medio",
        fix_group="iac",
        references=(
            _TF_AWS + "db_instance",
            _TF_AWS + "rds_cluster",
            _TF_AWS + "ebs_volume",
            _TF_AWS + "elasticache_replication_group",
            "https://cwe.mitre.org/data/definitions/311.html",
        ),
        cwe="CWE-311",
        owasp="A02:2021",
        cis=("3.10", "3.11"),
        lgpd=True,
        tags=("nuvem", "terraform", "criptografia"),
    ),
    KBEntry(
        id=DB_PUBLIC,
        title="Banco de dados da nuvem acessível pela Internet",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary="O banco é criado com endereço público (publicly_accessible = true).",
        explanation=(
            "Com publicly_accessible = true, a instância recebe um endereço acessível de fora da "
            "rede privada. O padrão do Terraform é false: esse valor foi escolhido de propósito ou "
            "copiado de um exemplo. Bancos de dados devem ficar em sub-redes privadas e ser "
            "alcançados só pela aplicação."
        ),
        risk=(
            "O banco fica ao alcance de quem varre a Internet atrás de senhas fracas e versões "
            "vulneráveis. A única barreira que sobra é o security group e a senha."
        ),
        steps=(
            "Defina publicly_accessible = false e coloque o banco em sub-redes privadas.",
            "Libere o acesso apenas pelo security group da aplicação.",
            "Para acessar de fora (administração), use VPN ou um túnel pelo bastion/Systems Manager.",
        ),
        examples=(
            _terraform(
                'resource "aws_db_instance" "principal" {\n'
                "  # ...\n"
                "  publicly_accessible    = false\n"
                "  db_subnet_group_name   = aws_db_subnet_group.privada.name\n"
                "  vpc_security_group_ids = [aws_security_group.banco.id]\n"
                "}",
            ),
        ),
        verify=(
            "'aws rds describe-db-instances --query \"DBInstances[].PubliclyAccessible\"' deve "
            "mostrar false. Rode o EIGAN de novo."
        ),
        effort="medio",
        fix_group="iac",
        references=(
            _TF_AWS + "db_instance",
            _TF_AWS + "redshift_cluster",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html",
            "https://cwe.mitre.org/data/definitions/668.html",
        ),
        cwe="CWE-668",
        owasp="A05:2021",
        cis=("4.4", "12.2"),
        lgpd=True,
        tags=("nuvem", "terraform", "banco-de-dados"),
    ),
)
