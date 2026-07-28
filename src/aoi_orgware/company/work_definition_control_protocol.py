"""Strict resident control envelopes for immutable work definitions.

This module admits only transport-shaped requests.  It deliberately performs
no ledger mutation and owns neither timestamps nor Chief authority; those are
the responsibility of the resident Supervisor.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import re
from collections.abc import Mapping
from typing import Any, NoReturn, cast

from .contracts import (
    WORK_PACKET_PROMPT_MEDIA_TYPE,
    validate_task_revision,
    validate_work_context_manifest,
    validate_work_definition_bundle,
    validate_work_packet,
)


WORK_DEFINITION_REGISTER_SCHEMA = "aoi.company.work-definition-register.v1"
WORK_DEFINITION_REGISTER_RESULT_SCHEMA = (
    "aoi.company.work-definition-register-result.v1"
)
WORK_DEFINITION_ENFORCEMENT_ACTIVATE_SCHEMA = (
    "aoi.company.work-definition-enforcement-activate.v1"
)
WORK_DEFINITION_ENFORCEMENT_RESULT_SCHEMA = (
    "aoi.company.work-definition-enforcement-result.v1"
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MAX_PROMPT_BYTES = 256 * 1024


class WorkDefinitionControlProtocolError(ValueError):
    """An untrusted work-definition control envelope is malformed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> NoReturn:
    raise WorkDefinitionControlProtocolError(code)


def _exact_object(value: object, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("invalid_request_fields")
    return dict(cast(Mapping[str, object], value))


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _positive_int(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(code)
    return value


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _binding(
    value: Mapping[str, object],
) -> tuple[str, str, int, int, str]:
    return (
        _identifier(value["service_instance_id"], "invalid_service_instance_id"),
        _identifier(value["company_id"], "invalid_company_id"),
        _positive_int(value["company_incarnation"], "invalid_company_incarnation"),
        _positive_int(
            value["lock_domain_generation"],
            "invalid_lock_domain_generation",
        ),
        _sha256(value["manifest_sha256"], "invalid_manifest_sha256"),
    )


def _chief(
    value: Mapping[str, object],
) -> tuple[str, str, int, int, str]:
    return (
        _identifier(value["chief_id"], "invalid_chief_id"),
        _identifier(value["carrier_id"], "invalid_carrier_id"),
        _positive_int(value["term"], "invalid_term"),
        _positive_int(value["epoch"], "invalid_epoch"),
        _identifier(value["chief_execution_id"], "invalid_chief_execution_id"),
    )


def _prompt(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        _fail("invalid_prompt_base64")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        _fail("invalid_prompt_base64")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        _fail("invalid_prompt_base64")
    if (
        not decoded
        or len(decoded) > _MAX_PROMPT_BYTES
        or base64.b64encode(decoded) != encoded
    ):
        _fail("invalid_prompt_base64")
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid_prompt_utf8")
    if "\x00" in text or text.encode("utf-8") != decoded:
        _fail("invalid_prompt_utf8")
    return decoded


def _work_bundle(
    task_revision: object,
    work_packet: object,
    context_manifest: object,
    *,
    company_id: str,
    company_incarnation: int,
    lock_domain_generation: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        task = validate_task_revision(task_revision)
    except ValueError:
        _fail("invalid_task_revision")
    try:
        packet = validate_work_packet(work_packet)
    except ValueError:
        _fail("invalid_work_packet")
    try:
        context = validate_work_context_manifest(context_manifest)
    except ValueError:
        _fail("invalid_context_manifest")
    if any(
        item["company_id"] != company_id
        or item["company_incarnation"] != company_incarnation
        or item["lock_domain_generation"] != lock_domain_generation
        for item in (task, packet, context)
    ):
        _fail("invalid_company_binding")
    try:
        validate_work_definition_bundle(task, packet, context)
    except ValueError:
        _fail("invalid_work_definition_bundle")
    return task, packet, context


def _match_prompt(packet: Mapping[str, Any], prompt_bytes: bytes) -> None:
    reference = packet["prompt_ref"]
    if (
        reference["availability"] != "available"
        or reference["media_type"] != WORK_PACKET_PROMPT_MEDIA_TYPE
        or reference["size_bytes"] != len(prompt_bytes)
        or reference["sha256"] != hashlib.sha256(prompt_bytes).hexdigest()
    ):
        _fail("prompt_ref_mismatch")


@dataclass(frozen=True, slots=True)
class WorkDefinitionRegisterCommand:
    """A validated definition-registration request, not a registration result."""

    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    chief_id: str
    carrier_id: str
    term: int
    epoch: int
    chief_execution_id: str
    transaction_id: str
    command_id: str
    task_revision: dict[str, Any]
    work_packet: dict[str, Any]
    context_manifest: dict[str, Any]
    prompt_bytes: bytes

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": WORK_DEFINITION_REGISTER_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "company_id": self.company_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "chief_id": self.chief_id,
            "carrier_id": self.carrier_id,
            "term": self.term,
            "epoch": self.epoch,
            "chief_execution_id": self.chief_execution_id,
            "transaction_id": self.transaction_id,
            "command_id": self.command_id,
            "task_revision": self.task_revision,
            "work_packet": self.work_packet,
            "context_manifest": self.context_manifest,
            "prompt_base64": base64.b64encode(self.prompt_bytes).decode("ascii"),
        }


@dataclass(frozen=True, slots=True)
class WorkDefinitionEnforcementActivateCommand:
    """A one-way enforcement activation request; activation time is server-owned."""

    service_instance_id: str
    company_id: str
    company_incarnation: int
    lock_domain_generation: int
    manifest_sha256: str
    chief_id: str
    carrier_id: str
    term: int
    epoch: int
    chief_execution_id: str
    transaction_id: str
    command_id: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": WORK_DEFINITION_ENFORCEMENT_ACTIVATE_SCHEMA,
            "service_instance_id": self.service_instance_id,
            "company_id": self.company_id,
            "company_incarnation": self.company_incarnation,
            "lock_domain_generation": self.lock_domain_generation,
            "manifest_sha256": self.manifest_sha256,
            "chief_id": self.chief_id,
            "carrier_id": self.carrier_id,
            "term": self.term,
            "epoch": self.epoch,
            "chief_execution_id": self.chief_execution_id,
            "transaction_id": self.transaction_id,
            "command_id": self.command_id,
        }


_REGISTER_FIELDS = frozenset({
    "schema_version", "service_instance_id", "company_id", "company_incarnation",
    "lock_domain_generation", "manifest_sha256", "chief_id", "carrier_id",
    "term", "epoch", "chief_execution_id", "transaction_id", "command_id",
    "task_revision", "work_packet", "context_manifest", "prompt_base64",
})
_ENFORCEMENT_FIELDS = frozenset({
    "schema_version", "service_instance_id", "company_id", "company_incarnation",
    "lock_domain_generation", "manifest_sha256", "chief_id", "carrier_id",
    "term", "epoch", "chief_execution_id", "transaction_id", "command_id",
})


def parse_work_definition_register(value: object) -> WorkDefinitionRegisterCommand:
    """Parse one fully bounded immutable work-definition registration request."""

    item = _exact_object(value, _REGISTER_FIELDS)
    if item["schema_version"] != WORK_DEFINITION_REGISTER_SCHEMA:
        _fail("invalid_schema_version")
    (
        service_instance_id,
        company_id,
        company_incarnation,
        lock_domain_generation,
        manifest_sha256,
    ) = _binding(item)
    chief_id, carrier_id, term, epoch, chief_execution_id = _chief(item)
    task, packet, context = _work_bundle(
        item["task_revision"], item["work_packet"], item["context_manifest"],
        company_id=company_id,
        company_incarnation=company_incarnation,
        lock_domain_generation=lock_domain_generation,
    )
    prompt_bytes = _prompt(item["prompt_base64"])
    _match_prompt(packet, prompt_bytes)
    return WorkDefinitionRegisterCommand(
        service_instance_id=service_instance_id,
        company_id=company_id,
        company_incarnation=company_incarnation,
        lock_domain_generation=lock_domain_generation,
        manifest_sha256=manifest_sha256,
        chief_id=chief_id,
        carrier_id=carrier_id,
        term=term,
        epoch=epoch,
        chief_execution_id=chief_execution_id,
        transaction_id=_identifier(item["transaction_id"], "invalid_transaction_id"),
        command_id=_identifier(item["command_id"], "invalid_command_id"),
        task_revision=task,
        work_packet=packet,
        context_manifest=context,
        prompt_bytes=prompt_bytes,
    )


def parse_work_definition_enforcement_activate(
    value: object,
) -> WorkDefinitionEnforcementActivateCommand:
    """Parse an activation request without deciding authority or recording time."""

    item = _exact_object(value, _ENFORCEMENT_FIELDS)
    if item["schema_version"] != WORK_DEFINITION_ENFORCEMENT_ACTIVATE_SCHEMA:
        _fail("invalid_schema_version")
    (
        service_instance_id,
        company_id,
        company_incarnation,
        lock_domain_generation,
        manifest_sha256,
    ) = _binding(item)
    chief_id, carrier_id, term, epoch, chief_execution_id = _chief(item)
    return WorkDefinitionEnforcementActivateCommand(
        service_instance_id=service_instance_id,
        company_id=company_id,
        company_incarnation=company_incarnation,
        lock_domain_generation=lock_domain_generation,
        manifest_sha256=manifest_sha256,
        chief_id=chief_id,
        carrier_id=carrier_id,
        term=term,
        epoch=epoch,
        chief_execution_id=chief_execution_id,
        transaction_id=_identifier(item["transaction_id"], "invalid_transaction_id"),
        command_id=_identifier(item["command_id"], "invalid_command_id"),
    )


__all__ = [
    "WORK_DEFINITION_ENFORCEMENT_ACTIVATE_SCHEMA",
    "WORK_DEFINITION_ENFORCEMENT_RESULT_SCHEMA",
    "WORK_DEFINITION_REGISTER_RESULT_SCHEMA",
    "WORK_DEFINITION_REGISTER_SCHEMA",
    "WorkDefinitionControlProtocolError",
    "WorkDefinitionEnforcementActivateCommand",
    "WorkDefinitionRegisterCommand",
    "parse_work_definition_enforcement_activate",
    "parse_work_definition_register",
]
