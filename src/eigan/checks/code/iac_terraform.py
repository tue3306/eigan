"""Regras para Terraform: armazenamento público, firewall aberto, criptografia e banco público.

Cada pasta é um módulo (ver ``iac_tf_model``). Os defaults usados aqui são os da
documentação do provedor AWS do Terraform: ``storage_encrypted`` é ``false`` quando ausente
em ``aws_db_instance`` e em ``aws_rds_cluster`` provisionado; nos demais recursos o valor
depende da conta (criptografia padrão do EBS, por exemplo), então só ``false`` explícito conta.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...core.models import Confidence
from .iac_common import DB_PUBLIC, NO_ENCRYPTION, IacReport
from .iac_hcl import Block
from .iac_tf_model import Module, Resource, TfRun, as_text
from .iac_tf_network import check_network
from .iac_tf_storage import check_storage


@dataclass(frozen=True)
class _Encryption:
    """Argumento de criptografia de um tipo de recurso."""

    argument: str
    label: str
    #: ausente equivale a ``false`` (documentado), salvo quando algum destes argumentos existe
    default_off_unless: tuple[str, ...] | None = None


_ENCRYPTION: dict[str, tuple[_Encryption, ...]] = {
    "aws_db_instance": (
        _Encryption(
            "storage_encrypted",
            "o disco do banco de dados",
            (
                "replicate_source_db",
                "snapshot_identifier",
                "kms_key_id",
                "restore_to_point_in_time",
            ),
        ),
    ),
    "aws_rds_cluster": (
        _Encryption(
            "storage_encrypted",
            "o cluster de banco de dados",
            (
                "replication_source_identifier",
                "snapshot_identifier",
                "global_cluster_identifier",
                "kms_key_id",
                "restore_to_point_in_time",
            ),
        ),
    ),
    "aws_ebs_volume": (_Encryption("encrypted", "o volume EBS"),),
    "aws_efs_file_system": (_Encryption("encrypted", "o sistema de arquivos EFS"),),
    "aws_redshift_cluster": (_Encryption("encrypted", "o cluster Redshift"),),
    "aws_elasticache_replication_group": (
        _Encryption("at_rest_encryption_enabled", "os dados em repouso do cache"),
        _Encryption("transit_encryption_enabled", "o tráfego do cache"),
    ),
}
_INSTANCE_DISKS = ("root_block_device", "ebs_block_device")
_PUBLIC_DATABASES = ("aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster")


def check_terraform(files: dict[str, str]) -> dict[str, IacReport]:
    """Analisa os ``.tf`` de **uma pasta** e devolve o relatório de cada arquivo."""
    run = TfRun(Module(files), {rel: IacReport() for rel in files})
    check_storage(run)
    check_network(run)
    for resource in run.module.resources:
        for rule in _ENCRYPTION.get(resource.type, ()):
            _encryption(run, resource, rule)
        if resource.type == "aws_instance":
            _instance_disks(run, resource)
        if resource.type in _PUBLIC_DATABASES:
            _public_database(run, resource)
    return run.reports


def _encryption(run: TfRun, resource: Resource, rule: _Encryption) -> None:
    block = resource.block
    value, indirect = run.module.flag(block.get(rule.argument))
    if value is True:
        run.strength(resource, "code.iac.criptografia", f"{rule.argument} = true")
    elif value is False:
        _encryption_off(
            run,
            resource,
            rule,
            block.line_of(rule.argument),
            f"{rule.argument} = false",
            indirect,
            Confidence.CONFIRMED,
        )
    elif not block.has(rule.argument) and _missing_means_off(run, resource, rule):
        _encryption_off(
            run,
            resource,
            rule,
            block.line,
            f"{rule.argument} ausente (o padrão é false)",
            False,
            Confidence.FIRM,
        )


def _missing_means_off(run: TfRun, resource: Resource, rule: _Encryption) -> bool:
    block = resource.block
    if rule.default_off_unless is None:
        return False
    if any(block.has(argument) or block.children(argument) for argument in rule.default_off_unless):
        return False  # réplica ou restauração herda da origem; kms_key_id exige criptografia
    if resource.type == "aws_rds_cluster":
        mode = run.module.resolve(block.get("engine_mode"))[0]
        return block.get("engine_mode") is None or as_text(mode).lower() == "provisioned"
    return True


def _encryption_off(
    run: TfRun,
    resource: Resource,
    rule: _Encryption,
    line: int,
    what: str,
    indirect: bool,
    confidence: Confidence,
) -> None:
    run.issue(
        resource,
        NO_ENCRYPTION,
        line,
        f"{resource.address} deixa {rule.label} sem criptografia",
        f"{resource.address}: {what}",
        rule.argument,
        f"{rule.argument} = true",
        confidence=confidence,
        indirect=indirect,
        argumento=rule.argument,
    )


def _instance_disks(run: TfRun, resource: Resource) -> None:
    for kind in _INSTANCE_DISKS:
        for disk in resource.block.children(kind):
            _instance_disk(run, resource, kind, disk)


def _instance_disk(run: TfRun, resource: Resource, kind: str, disk: Block) -> None:
    value, indirect = run.module.flag(disk.get("encrypted"))
    if value is not False:
        return
    run.issue(
        resource,
        NO_ENCRYPTION,
        disk.line_of("encrypted"),
        f"{resource.address} tem um disco sem criptografia ({kind})",
        f"{resource.address}: {kind}.encrypted = false",
        f"{kind}:{as_text(disk.get('device_name')) or disk.line}",
        f"{kind} {{\n  encrypted = true\n}}",
        indirect=indirect,
        argumento=f"{kind}.encrypted",
    )


def _public_database(run: TfRun, resource: Resource) -> None:
    block = resource.block
    value, indirect = run.module.flag(block.get("publicly_accessible"))
    if value is False:
        run.strength(resource, "code.iac.banco_privado", "publicly_accessible = false")
    elif value is True:
        run.issue(
            resource,
            DB_PUBLIC,
            block.line_of("publicly_accessible"),
            f"{resource.address} fica acessível pela Internet",
            f"{resource.address}: publicly_accessible = true",
            "publicly_accessible",
            "publicly_accessible = false",
            indirect=indirect,
        )
