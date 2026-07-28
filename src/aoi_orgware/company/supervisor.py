"""Minimal single-writer company bootstrap for the v0.5 Command Center."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Self, cast

from .blobs import BlobStoreError
from .contracts import (
    ALERT_V1,
    AUTHORITY_GRANT_V1,
    BLOB_REF_V1,
    CARRIER_BINDING_V1,
    CHIEF_TERM_V1,
    COMPANY_MANIFEST_V1,
    CONTROL_INTENT_V1,
    DEPARTMENT_IDENTITY_V1,
    DEPARTMENT_LIFECYCLE_RECEIPT_V1,
    DEPARTMENT_LIFECYCLE_REQUEST_V1,
    DEPARTMENT_LIFECYCLE_RESULT_V1,
    DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
    DEPARTMENT_SNAPSHOT_V1,
    DISPATCH_REQUEST_V1,
    ENGINEERING_DISPOSITION_RECEIPT_V1,
    ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE,
    EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
    EXECUTION_RUNTIME_OBSERVATION_SOURCE_MEDIA_TYPE,
    EVIDENCE_RECORD_V1,
    EXECUTION_EVENT_V1,
    EXECUTION_NODE_V1,
    EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE,
    EXTERNAL_JOB_EFFECT_RECEIPT_V1,
    EXTERNAL_JOB_V1,
    MUTATION_INTENT_V1,
    MAX_NEEDS_USER_CONTENT_BYTES,
    NEEDS_USER_ANSWER_MEDIA_TYPE,
    NEEDS_USER_QUESTION_MEDIA_TYPE,
    NEEDS_USER_REVISION_V1,
    ORGANIZATION_NODE_V1,
    PROVIDER_COVERAGE_REVISION_V1,
    PROVIDER_LAUNCH_BINDING_V1,
    PROVIDER_LIFECYCLE_RECEIPT_V1,
    PROVIDER_LIFECYCLE_SOURCE_MEDIA_TYPE,
    PROVIDER_TURN_RESULT_RECEIPT_V1,
    PROVIDER_WORKER_IO_RECEIPT_V1,
    PROVIDER_WORKER_OPERATION_V1,
    PROVIDER_TELEMETRY_RAW_MEDIA_TYPE,
    PROVIDER_TELEMETRY_RECEIPT_V1,
    TASK_REVISION_V1,
    TAKEOVER_CAPABILITY_V1,
    TAKEOVER_CONSUMPTION_RECEIPT_V1,
    USAGE_COUNTER_SAMPLE_V1,
    WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
    WORK_DEFINITION_ENFORCEMENT_V1,
    WORK_DISPATCH_BINDING_V1,
    WORK_PACKET_PROMPT_MEDIA_TYPE,
    WORK_PACKET_V1,
    WORK_RESULT_RECEIPT_V1,
    ZERO_SHA256,
    authority_from_grant,
    canonical_company_json_bytes,
    canonical_provider_turn_result_bytes,
    company_contract_sha256,
    validate_authority_grant,
    validate_alert,
    validate_carrier_binding,
    validate_company_manifest,
    validate_control_intent,
    validate_department_lifecycle_request,
    validate_department_lifecycle_result,
    validate_department_snapshot_document,
    validate_dispatch_request,
    validate_engineering_disposition_receipt,
    validate_engineering_disposition_source,
    validate_evidence_record,
    validate_execution_event,
    validate_execution_node,
    validate_execution_runtime_observation_receipt,
    validate_execution_runtime_observation_source,
    validate_external_job_effect_receipt,
    validate_external_job_effect_source,
    validate_external_job,
    validate_mutation_intent,
    validate_provider_lifecycle_receipt,
    validate_provider_lifecycle_source,
    validate_provider_coverage_revision,
    validate_provider_turn_result,
    validate_provider_turn_result_receipt,
    validate_provider_telemetry_receipt,
    validate_needs_user_revision,
    validate_usage_counter_sample,
    validate_takeover_capability,
    validate_takeover_consumption_receipt,
    validate_task_revision,
    validate_work_context_manifest,
    validate_work_definition_bundle,
    validate_work_definition_enforcement,
    validate_work_dispatch_binding,
    validate_work_packet,
    validate_work_result_receipt,
)
from .dashboard import (
    CompanyDashboardServer,
    CompanyDashboardSnapshotCache,
)
from .ledger import (
    LedgerAppendResult,
    LedgerHeadsSnapshot,
    LedgerTransactionRecord,
)
from .invariants import (
    InvariantObject,
    MAX_ACTIVE_CARRIERS,
    MAX_MANAGER_ACTIVE_FANOUT,
    reduce_company_invariants,
    validate_provider_turn_result_lifecycle,
)
from .readmodel import ProjectedObject
from .state import (
    CompanyDeliveryPartialError,
    CompanyDeliverySnapshot,
    CompanyStateError,
    CompanyStateHealth,
    CompanyStateOwner,
)
from .transactions import CompanyEventDraft, build_company_transaction_request
from .telemetry import (
    NormalizedTelemetry,
    normalize_claude_telemetry,
    normalize_codex_telemetry,
    provider_native_relation_payload,
    telemetry_facts_payload,
)
from .telemetry_policy import (
    TelemetryPolicyError,
    automatic_coverage_state,
    coverage_event_kinds,
    exact_provider_telemetry_join,
    telemetry_id,
    unknown_drop,
)
from .views import CompanyViewService


class CompanySupervisorError(RuntimeError):
    """The narrow bootstrap boundary cannot establish durable company state."""


class CompanySupervisorDashboardRefreshError(CompanySupervisorError):
    """A mutation committed, but its Dashboard projection was not published."""

    def __init__(
        self,
        result: LedgerAppendResult | CompanyDeliverySnapshot,
    ) -> None:
        super().__init__(
            "company state changed but Dashboard refresh failed",
        )
        self.result = result


class CompanyChiefTakeoverError(CompanySupervisorError):
    """A Chief capability or handoff attempt is invalid or already fenced."""


class CompanyDepartmentLifecycleError(CompanySupervisorError):
    """A durable department lifecycle transition cannot be established."""


class CompanyDepartmentDispatchCapacityBlocked(CompanyDepartmentLifecycleError):
    """Admission is safely deferred because a typed capacity bound is full."""

    def __init__(self, reason: str) -> None:
        if reason not in {"capacity", "fanout", "unattributed"}:
            raise ValueError("department dispatch capacity reason is invalid")
        super().__init__(f"department dispatch admission is {reason}-blocked")
        self.reason = reason


class CompanyExecutionRegistrationError(CompanySupervisorError):
    """A provider-visible execution cannot be durably registered."""


class CompanyExternalJobError(CompanySupervisorError):
    """An external job lifecycle cannot be durably established."""


class CompanyTelemetryIngestError(CompanySupervisorError):
    """Provider telemetry cannot be durably represented without guessing."""


class CompanyNeedsUserError(CompanySupervisorError):
    """A cooperative Chief/user handoff is stale, malformed, or terminal."""


class CompanyWorkDefinitionError(CompanySupervisorError):
    """An immutable task/packet/context bundle cannot be durably registered."""


_PROVIDER_GRADE_PROVENANCE = frozenset({
    "provider_client_emitted",
    "adapter_receipt_persisted",
    "collector_received",
    "host_process_observed",
})
_MAX_EXTERNAL_JOB_EFFECT_SOURCE_BYTES = 256 * 1024
_MAX_WORK_PROMPT_BYTES = 256 * 1024
_MAX_WORK_RESULT_BYTES = 1024 * 1024


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value,
    )


@dataclass(frozen=True)
class ChiefTakeoverResult:
    """One durable takeover attempt, without exposing provider session IDs."""

    outcome: str
    receipt_state: str
    capability_id: str
    consumption_id: str
    transaction_id: str
    command_id: str
    chief_id: str
    carrier_id: str
    term: int | None
    epoch: int | None
    global_sequence: int
    idempotent_replay: bool


@dataclass(frozen=True)
class DepartmentLifecycleResult:
    """One durable department lifecycle or dispatch-queue transition."""

    operation: str
    department_id: str
    lifecycle_state: str
    snapshot_id: str
    snapshot_revision: int
    dispatch_request_id: str | None
    dispatch_state: str | None
    transaction_id: str
    command_id: str
    global_sequence: int
    idempotent_replay: bool


@dataclass(frozen=True)
class DepartmentDispatchResult:
    """One durable automatic department-dispatch revision."""

    dispatch_request_id: str
    dispatch_state: str
    revision: int
    transaction_id: str
    command_id: str
    receipt_state: str
    global_sequence: int
    execution_id: str | None
    carrier_id: str | None
    idempotent_replay: bool


@dataclass(frozen=True)
class ExecutionRuntimeStatusResult:
    """One durable provider-observed execution runtime status update."""

    execution_id: str
    engineering_status: str
    runtime_status: str
    transaction_id: str
    command_id: str
    global_sequence: int
    idempotent_replay: bool


@dataclass(frozen=True)
class ExternalJobLifecycleResult:
    """One durable queue, launch-admission, or observed job transition."""

    job_id: str
    job_state: str
    owner_execution_id: str
    job_execution_id: str
    mutation_intent_id: str
    mutation_state: str
    transaction_id: str
    command_id: str
    global_sequence: int
    idempotent_replay: bool


@dataclass(frozen=True)
class ProviderTelemetryIngestResult:
    """One immutable provider observation and its honest coverage revisions."""

    receipt_id: str
    provider: str
    parse_outcome: str
    normalized_kind: str
    dispatch_join_state: str
    lifecycle_coverage_revision_id: str
    usage_coverage_revision_id: str
    usage_sample_id: str | None
    transaction_id: str
    command_id: str
    global_sequence: int
    idempotent_replay: bool


@dataclass(frozen=True)
class ProviderCoverageResult:
    """One explicitly observed adapter/collector/spool/config coverage state."""

    coverage_scope_id: str
    coverage_surface: str
    revision_id: str
    revision: int
    state: str
    transaction_id: str
    command_id: str
    global_sequence: int
    idempotent_replay: bool


@dataclass(frozen=True)
class NeedsUserResult:
    """One immutable needs-user revision under the current logical Chief."""

    item_id: str
    revision_id: str
    revision: int
    state: str
    transaction_id: str
    command_id: str
    global_sequence: int
    idempotent_replay: bool


@dataclass(frozen=True)
class WorkDefinitionRegistrationResult:
    """One durable immutable work packet registration."""

    task_id: str
    task_revision_id: str
    packet_id: str
    transaction_id: str
    command_id: str
    global_sequence: int
    idempotent_replay: bool


@dataclass(frozen=True)
class WorkDefinitionEnforcementResult:
    """One durable, one-way registered-work launch enforcement activation."""

    gate_id: str
    mode: str
    transaction_id: str
    command_id: str
    global_sequence: int
    idempotent_replay: bool


# Compatibility name for the existing department-specific caller surface.
DepartmentExecutionStatusResult = ExecutionRuntimeStatusResult


class CompanySupervisor:
    """The only in-process lifetime owner of a company state incarnation.

    It supplies deterministic genesis plus the first durable Chief
    carrier-takeover boundary consumed by the read-only Command Center.
    Provider/session facts remain cooperative observations rather than
    provider-signed claims.
    """

    def __init__(self, state: CompanyStateOwner) -> None:
        self._state = state
        self._dashboard_cache: CompanyDashboardSnapshotCache | None = None
        self._dashboard_server: CompanyDashboardServer | None = None
        self._dashboard_environment_kind: str | None = None

    @property
    def slot_root(self) -> Path:
        """Return the active company slot without exposing mutation storage."""

        return self._state.registry.paths.root

    @property
    def manifest_path(self) -> Path:
        """Return the immutable registry manifest path for diagnostics."""

        return self._state.resolved.incarnation.manifest

    def health(self) -> CompanyStateHealth:
        """Return current durable state health through the single owner."""

        return self._state.health()

    def heads(self) -> LedgerHeadsSnapshot:
        """Return current ledger heads through the single owner."""

        return self._state.heads()

    def delivery(self) -> CompanyDeliverySnapshot:
        """Return the post-verified checkpoint/export delivery projection."""

        return self._state.delivery_snapshot()

    def _refresh_delivery_dashboard(
        self,
        result: CompanyDeliverySnapshot,
    ) -> None:
        cache = self._dashboard_cache
        if cache is None:
            return
        try:
            cache.refresh()
        except BaseException as exc:
            raise CompanySupervisorDashboardRefreshError(result) from exc

    def create_checkpoint_export(
        self,
        checkpoint_id: str,
        export_id: str,
        generated_at: str,
    ) -> CompanyDeliverySnapshot:
        """Create the checkpoint/export pair and publish partial truth too."""

        try:
            result = self._state.create_checkpoint_export_delivery(
                checkpoint_id,
                export_id,
                generated_at,
            )
        except CompanyDeliveryPartialError as exc:
            try:
                self._refresh_delivery_dashboard(exc.snapshot)
            except CompanySupervisorDashboardRefreshError as refresh_error:
                exc.add_note(
                    "Dashboard refresh also failed after partial checkpoint/export delivery: "
                    f"{refresh_error}",
                )
            raise
        self._refresh_delivery_dashboard(result)
        return result

    def objects(
        self,
        *,
        contract_type: str | None = None,
    ) -> tuple[ProjectedObject, ...]:
        """Return projected objects without exposing a writable state handle."""

        return self._state.objects(contract_type=contract_type)

    def register_work_definition(
        self,
        task_revision: Mapping[str, Any],
        work_packet: Mapping[str, Any],
        context_manifest: Mapping[str, Any],
        prompt_bytes: bytes,
        *,
        chief_id: str,
        carrier_id: str,
        term: int,
        epoch: int,
        chief_execution_id: str,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> WorkDefinitionRegistrationResult:
        """Persist an exact task/packet/context bundle under a Chief fence."""

        try:
            task = validate_task_revision(task_revision)
            packet = validate_work_packet(work_packet)
            context = validate_work_context_manifest(context_manifest)
        except ValueError as exc:
            raise CompanyWorkDefinitionError(
                "work definition contract is invalid",
            ) from exc
        if (
            type(prompt_bytes) is not bytes
            or not prompt_bytes
            or len(prompt_bytes) > _MAX_WORK_PROMPT_BYTES
        ):
            raise CompanyWorkDefinitionError(
                "work definition prompt bytes are invalid",
            )
        try:
            prompt_text = prompt_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CompanyWorkDefinitionError(
                "work definition prompt is not UTF-8",
            ) from exc
        if prompt_text.encode("utf-8") != prompt_bytes or "\x00" in prompt_text:
            raise CompanyWorkDefinitionError(
                "work definition prompt is not canonical UTF-8 text",
            )
        binding = self._binding()
        if any(
            {
                key: value[key]
                for key in (
                    "company_id",
                    "company_incarnation",
                    "lock_domain_generation",
                )
            }
            != binding
            for value in (task, packet, context)
        ):
            raise CompanyWorkDefinitionError(
                "work definition belongs to another company binding",
            )
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            self._require_exact_chief_dispatch_fence(
                chief_id=chief_id,
                carrier_id=carrier_id,
                term=term,
                epoch=epoch,
                chief_execution_id=chief_execution_id,
            )
            _require_durable_work_definition_chief_fence(
                durable,
                chief_id=chief_id,
                carrier_id=carrier_id,
                term=term,
                epoch=epoch,
            )
            try:
                durable_prompt = (
                    self._state._read_work_prompt_unlocked(  # noqa: SLF001
                        packet["prompt_ref"],
                    )
                )
                durable_context = (
                    self._state._read_work_context_manifest_unlocked(  # noqa: SLF001
                        packet["context_manifest_ref"],
                    )
                )
            except CompanyStateError as exc:
                raise CompanyWorkDefinitionError(
                    "durable work definition CAS bytes cannot be verified",
                ) from exc
            if (
                durable_prompt != prompt_bytes
                or durable_context != context
            ):
                raise CompanyWorkDefinitionError(
                    "durable work definition CAS bytes differ",
                )
            return _work_definition_result_from_record(
                durable,
                task=task,
                packet=packet,
                transaction_id=transaction_id,
                command_id=command_id,
                recorded_at=recorded_at,
                idempotent_replay=True,
            )

        # This fence must precede every CAS write.  A stale carrier is allowed
        # neither to mutate the ledger nor to leave orphaned prompt/context
        # blobs which could later be mistaken for a registered work definition.
        self._require_exact_chief_dispatch_fence(
            chief_id=chief_id,
            carrier_id=carrier_id,
            term=term,
            epoch=epoch,
            chief_execution_id=chief_execution_id,
        )
        _grant, authority, _execution = self._current_chief_mutation_context()
        current_task = self._state.readmodel.object(
            TASK_REVISION_V1,
            str(task["task_revision_id"]),
        )
        if (
            current_task is not None
            and _plain(current_task.payload) != task
        ):
            raise CompanyWorkDefinitionError(
                "task revision ID has divergent durable bytes",
            )
        current_packet = self._state.readmodel.object(
            WORK_PACKET_V1,
            str(packet["packet_id"]),
        )
        if current_packet is not None:
            raise CompanyWorkDefinitionError(
                "work packet ID is already durable",
            )
        context_bytes = canonical_company_json_bytes(context)
        prompt_metadata = self._state.blobs.put(prompt_bytes)
        context_metadata = self._state.blobs.put(context_bytes)
        if (
            self._state.blobs.read(prompt_metadata.sha256) != prompt_bytes
            or self._state.blobs.read(context_metadata.sha256) != context_bytes
        ):
            raise CompanyWorkDefinitionError(
                "work definition CAS readback differs",
            )
        expected_prompt_ref = _blob_ref(
            prompt_metadata.sha256,
            prompt_metadata.size_bytes,
            WORK_PACKET_PROMPT_MEDIA_TYPE,
        )
        expected_context_ref = _blob_ref(
            context_metadata.sha256,
            context_metadata.size_bytes,
            WORK_CONTEXT_MANIFEST_MEDIA_TYPE,
        )
        if (
            packet["prompt_ref"] != expected_prompt_ref
            or packet["context_manifest_ref"] != expected_context_ref
        ):
            raise CompanyWorkDefinitionError(
                "work packet differs from prompt or context CAS bytes",
            )
        parent = None
        parent_context = None
        if packet["parent_packet_id"] is not None:
            projected_parent = self._state.readmodel.object(
                WORK_PACKET_V1,
                str(packet["parent_packet_id"]),
            )
            if projected_parent is None:
                raise CompanyWorkDefinitionError(
                    "work packet parent is not durable",
                )
            parent = _plain(projected_parent.payload)
            try:
                parent_context_bytes = self._state.blobs.read(
                    str(parent["context_manifest_ref"]["sha256"]),
                )
                parent_context = validate_work_context_manifest(
                    json.loads(parent_context_bytes.decode("utf-8")),
                )
                if (
                    canonical_company_json_bytes(parent_context)
                    != parent_context_bytes
                ):
                    raise CompanyWorkDefinitionError(
                        "parent work context is not canonical",
                    )
            except CompanyWorkDefinitionError:
                raise
            except (
                BlobStoreError,
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValueError,
                KeyError,
                TypeError,
            ) as exc:
                raise CompanyWorkDefinitionError(
                    "parent work context cannot be verified",
                ) from exc
        try:
            validated_bundle = validate_work_definition_bundle(
                task,
                packet,
                context,
                parent_packet=parent,
                parent_context_manifest=parent_context,
            )
        except ValueError as exc:
            raise CompanyWorkDefinitionError(
                "work definition bundle is invalid",
            ) from exc
        for reference in validated_bundle["context_derivation"][
            "added_upstream_result_refs"
        ]:
            matching_results = [
                item
                for item in self.objects(
                    contract_type=WORK_RESULT_RECEIPT_V1,
                )
                if (
                    item.payload["packet_id"]
                    == packet["parent_packet_id"]
                    and item.payload["producer_execution_id"]
                    == packet["parent_execution_id"]
                    and _plain(item.payload["result_ref"]) == reference
                )
            ]
            if len(matching_results) != 1:
                raise CompanyWorkDefinitionError(
                    "work context upstream result lacks one durable producer",
                )

        drafts: list[CompanyEventDraft] = []
        if current_task is None:
            drafts.append(CompanyEventDraft(
                event_id=_work_definition_id(
                    binding,
                    "task-event",
                    transaction_id,
                ),
                event_type="work.task.registered",
                recorded_at=recorded_at,
                payload=task,
            ))
        drafts.append(CompanyEventDraft(
            event_id=_work_definition_id(
                binding,
                "packet-event",
                transaction_id,
            ),
            event_type="work.packet.registered",
            recorded_at=recorded_at,
            payload=packet,
        ))
        request = build_company_transaction_request(
            self.heads(),
            authority,
            transaction_id=transaction_id,
            command_id=command_id,
            events=drafts,
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _work_definition_result_from_record(
            committed.record,
            task=task,
            packet=packet,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            idempotent_replay=committed.idempotent_replay,
        )

    def activate_work_definition_enforcement(
        self,
        *,
        chief_id: str,
        carrier_id: str,
        term: int,
        epoch: int,
        chief_execution_id: str,
        transaction_id: str,
        command_id: str,
        activated_at: str,
    ) -> WorkDefinitionEnforcementResult:
        """Irreversibly require registered bindings for future launches."""

        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            self._require_exact_chief_dispatch_fence(
                chief_id=chief_id,
                carrier_id=carrier_id,
                term=term,
                epoch=epoch,
                chief_execution_id=chief_execution_id,
            )
            _require_durable_work_definition_chief_fence(
                durable,
                chief_id=chief_id,
                carrier_id=carrier_id,
                term=term,
                epoch=epoch,
            )
            return _work_definition_enforcement_result_from_record(
                durable,
                transaction_id=transaction_id,
                command_id=command_id,
                activated_at=activated_at,
                idempotent_replay=True,
            )
        self._require_exact_chief_dispatch_fence(
            chief_id=chief_id,
            carrier_id=carrier_id,
            term=term,
            epoch=epoch,
            chief_execution_id=chief_execution_id,
        )
        if self.objects(contract_type=WORK_DEFINITION_ENFORCEMENT_V1):
            raise CompanyWorkDefinitionError(
                "work definition enforcement is already active",
            )
        _grant, authority, _execution = self._current_chief_mutation_context()
        heads = self.heads()
        gate_unsigned = {
            "contract_type": WORK_DEFINITION_ENFORCEMENT_V1,
            "schema_version": 1,
            **self._binding(),
            "gate_id": "work-definition-enforcement",
            "mode": "registered_launch_required",
            "previous_transaction_sha256":
                heads.global_head.transaction_sha256,
            "activated_at": activated_at,
            "observation": {"state": "known", "reason": "observed"},
        }
        try:
            gate = validate_work_definition_enforcement({
                **gate_unsigned,
                "enforcement_sha256":
                    company_contract_sha256(gate_unsigned),
            })
        except ValueError as exc:
            raise CompanyWorkDefinitionError(
                "work definition enforcement contract is invalid",
            ) from exc
        request = build_company_transaction_request(
            heads,
            authority,
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                CompanyEventDraft(
                    event_id=_work_definition_id(
                        self._binding(),
                        "enforcement-event",
                        transaction_id,
                    ),
                    event_type="work.definition.enforcement.activated",
                    recorded_at=activated_at,
                    payload=gate,
                    provenance="AOI_verified",
                ),
            ],
        )
        committed = self.commit(request, recorded_at=activated_at)
        return _work_definition_enforcement_result_from_record(
            committed.record,
            transaction_id=transaction_id,
            command_id=command_id,
            activated_at=activated_at,
            idempotent_replay=committed.idempotent_replay,
        )

    def records_after(
        self,
        global_sequence: int,
        *,
        limit: int = 1024,
    ) -> tuple[LedgerTransactionRecord, ...]:
        """Return bounded immutable ledger records through the single owner."""

        return self._state.records_after(global_sequence, limit=limit)

    def record_by_transaction_id(
        self,
        transaction_id: str,
    ) -> LedgerTransactionRecord | None:
        """Return one exact durable transaction for owner-side reconciliation."""

        return self._state.record_by_transaction_id(transaction_id)

    def commit(
        self,
        request: Mapping[str, Any],
        *,
        state: str = "committed",
        evidence: Sequence[Mapping[str, Any]] = (),
        recorded_at: str | None = None,
        crash_at: str | None = None,
    ) -> LedgerAppendResult:
        """Commit once and synchronously publish any active Dashboard cache."""

        result = self._state.commit(
            request,
            state=state,
            evidence=evidence,
            recorded_at=recorded_at,
            crash_at=crash_at,
        )
        cache = self._dashboard_cache
        if cache is not None:
            try:
                cache.refresh()
            except BaseException as exc:
                raise CompanySupervisorDashboardRefreshError(result) from exc
        return result

    def ingest_codex_telemetry(
        self,
        raw: bytes,
        *,
        adapter_instance_id: str,
        adapter_event_id: str,
        intake_sequence: int,
        transaction_id: str,
        command_id: str,
        received_at: str,
    ) -> ProviderTelemetryIngestResult:
        """Persist one bounded Codex adapter occurrence without inferring lineage."""

        return self._ingest_provider_telemetry(
            normalize_codex_telemetry(raw), raw,
            adapter_instance_id=adapter_instance_id,
            adapter_event_id=adapter_event_id,
            intake_sequence=intake_sequence,
            transaction_id=transaction_id,
            command_id=command_id,
            received_at=received_at,
        )

    def ingest_claude_telemetry(
        self,
        raw: bytes,
        *,
        source_class: str,
        adapter_instance_id: str,
        adapter_event_id: str,
        intake_sequence: int,
        transaction_id: str,
        command_id: str,
        received_at: str,
    ) -> ProviderTelemetryIngestResult:
        """Persist one Claude hook/OTel occurrence without manufacturing tokens."""

        if source_class not in {"claude_hook", "otel"}:
            raise CompanyTelemetryIngestError("Claude source_class is invalid")
        return self._ingest_provider_telemetry(
            normalize_claude_telemetry(raw, cast(Any, source_class)), raw,
            adapter_instance_id=adapter_instance_id,
            adapter_event_id=adapter_event_id,
            intake_sequence=intake_sequence,
            transaction_id=transaction_id,
            command_id=command_id,
            received_at=received_at,
        )

    def _ingest_provider_telemetry(
        self,
        normalized: NormalizedTelemetry,
        raw: bytes,
        *,
        adapter_instance_id: str,
        adapter_event_id: str,
        intake_sequence: int,
        transaction_id: str,
        command_id: str,
        received_at: str,
    ) -> ProviderTelemetryIngestResult:
        """Build the sole-writer telemetry transaction from one parser result."""

        if type(raw) is not bytes or normalized.raw_sha256 != hashlib.sha256(raw).hexdigest() or normalized.raw_size_bytes != len(raw):
            raise CompanyTelemetryIngestError("telemetry raw bytes differ from normalization")
        if not isinstance(intake_sequence, int) or isinstance(intake_sequence, bool) or intake_sequence < 1:
            raise CompanyTelemetryIngestError("telemetry intake sequence is invalid")
        durable = self._state.record_by_transaction_id(transaction_id)
        occurrence = self._telemetry_occurrences(adapter_instance_id, adapter_event_id)
        if durable is not None:
            return self._telemetry_replay(
                durable, normalized=normalized, adapter_instance_id=adapter_instance_id,
                adapter_event_id=adapter_event_id, intake_sequence=intake_sequence,
                transaction_id=transaction_id, command_id=command_id,
                received_at=received_at,
            )
        if occurrence:
            receipt, record = occurrence[0]
            if len(occurrence) != 1:
                raise CompanyTelemetryIngestError("telemetry occurrence is ambiguous")
            if (
                receipt["raw_artifact"]["sha256"] != normalized.raw_sha256
                or receipt["raw_artifact"]["size_bytes"] != len(raw)
                or receipt["intake_sequence"] != intake_sequence
                or receipt["provider"] != normalized.provider
                or receipt["source_class"] != normalized.source_class
                or receipt["transaction_id"] != transaction_id
                or receipt["command_id"] != command_id
                or receipt["received_at"] != received_at
            ):
                raise CompanyTelemetryIngestError("telemetry occurrence differs from durable bytes")
            return _telemetry_result_from_record(record, idempotent_replay=True)

        metadata = self._state.blobs.put(raw)
        raw_artifact = _blob_ref(
            metadata.sha256, metadata.size_bytes, PROVIDER_TELEMETRY_RAW_MEDIA_TYPE,
        )
        binding = self._binding()
        join = self._exact_telemetry_join(normalized, registry_cursor=self.heads().global_head.global_sequence)
        receipt_id = _telemetry_id(binding, "receipt", adapter_instance_id, adapter_event_id)
        receipt = _provider_telemetry_receipt_payload(
            binding, normalized=normalized, raw_artifact=raw_artifact, join=join,
            receipt_id=receipt_id, adapter_instance_id=adapter_instance_id,
            adapter_event_id=adapter_event_id, intake_sequence=intake_sequence,
            transaction_id=transaction_id, command_id=command_id, received_at=received_at,
        )
        prior_sequence = self._last_adapter_sequence(
            normalized.provider, normalized.source_class, adapter_instance_id,
        )
        lifecycle_state, lifecycle_reason, lifecycle_drop = _automatic_coverage_state(
            normalized.parse_outcome, prior_sequence, intake_sequence,
            prior=self._latest_coverage(
                normalized.provider, normalized.source_class, adapter_instance_id, "lifecycle",
            ),
        )
        if (
            normalized.parse_outcome == "normalized"
            and join["state"] != "exact"
            and lifecycle_state == "observed"
        ):
            lifecycle_state = "degraded"
            lifecycle_reason = (
                "provider_telemetry_unattributed"
                if join["state"] == "none"
                else "provider_telemetry_attribution_ambiguous"
            )
            lifecycle_drop = _unknown_drop(lifecycle_reason)
        lifecycle = self._next_coverage_revision(
            provider=normalized.provider, source_class=normalized.source_class,
            adapter_instance_id=adapter_instance_id, surface="lifecycle",
            declared_event_kinds=_coverage_event_kinds(
                normalized.provider, normalized.source_class, "lifecycle",
            ), state=lifecycle_state,
            reason=lifecycle_reason, assessment_source="receipt", receipt=receipt,
            dropped_event_count=lifecycle_drop, assessed_at=received_at,
        )
        usage_sample: dict[str, Any] | None = None
        usage_state: str | None
        usage_reason: str | None
        usage_drop: dict[str, Any] | None
        usage_kinds: list[str]
        if normalized.raw_cumulative_tokens is not None:
            usage_sample = _usage_counter_sample_payload(
                binding, normalized=normalized, raw_artifact=raw_artifact, receipt=receipt,
                sample_id=_telemetry_id(binding, "usage-sample", adapter_instance_id, adapter_event_id),
                adapter_instance_id=adapter_instance_id, adapter_event_id=adapter_event_id,
                intake_sequence=intake_sequence, received_at=received_at,
            )
            usage_state, usage_reason, usage_drop = lifecycle_state, lifecycle_reason, lifecycle_drop
            usage_kinds = _coverage_event_kinds(normalized.provider, normalized.source_class, "usage")
        elif normalized.provider == "claude":
            usage_state, usage_reason, usage_drop = "unavailable", "provider_usage_unavailable", _unknown_drop("provider_usage_unavailable")
            usage_kinds = _coverage_event_kinds(normalized.provider, normalized.source_class, "usage")
        else:
            usage_state = usage_reason = None
            usage_drop = None
            usage_kinds = []
        usage: dict[str, Any] | None = None
        if usage_state is not None and usage_reason is not None and usage_drop is not None:
            usage = self._next_coverage_revision(
                provider=normalized.provider, source_class=normalized.source_class,
                adapter_instance_id=adapter_instance_id, surface="usage", declared_event_kinds=usage_kinds,
                state=usage_state, reason=usage_reason, assessment_source="receipt", receipt=receipt,
                dropped_event_count=usage_drop, assessed_at=received_at,
            )
        payloads = [receipt, lifecycle, *([] if usage_sample is None else [usage_sample]), *([] if usage is None else [usage])]
        event_labels = ["provider.telemetry.received", "provider.coverage.lifecycle", *([] if usage_sample is None else ["usage.counter.observed"]), *([] if usage is None else ["provider.coverage.usage"])]
        drafts = [
            CompanyEventDraft(
                event_id=_telemetry_id(binding, "event", transaction_id, str(index)),
                event_type=label, recorded_at=received_at, payload=payload,
                provenance="adapter_receipt_persisted",
            )
            for index, (label, payload) in enumerate(zip(event_labels, payloads, strict=True), start=1)
        ]
        request = build_company_transaction_request(
            self.heads(), self._supervisor_authority(), transaction_id=transaction_id,
            command_id=command_id, events=drafts,
        )
        committed = self.commit(request, recorded_at=received_at)
        return _telemetry_result_from_record(committed.record, idempotent_replay=committed.idempotent_replay)

    def record_provider_coverage(
        self,
        *,
        provider: str,
        source_class: str,
        adapter_instance_id: str,
        coverage_surface: str,
        declared_event_kinds: Sequence[str],
        state: str,
        reason: str,
        assessment_source: str,
        dropped_event_count: Mapping[str, Any],
        assessed_at: str,
        transaction_id: str,
        command_id: str,
    ) -> ProviderCoverageResult:
        """Persist an explicit health assessment; silence never becomes loss."""

        if coverage_surface not in {"lifecycle", "usage", "collector"}:
            raise CompanyTelemetryIngestError("coverage surface is invalid")
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _coverage_result_from_record(durable, transaction_id, command_id, True)
        coverage = self._next_coverage_revision(
            provider=provider, source_class=source_class, adapter_instance_id=adapter_instance_id,
            surface=coverage_surface, declared_event_kinds=list(declared_event_kinds), state=state,
            reason=reason, assessment_source=assessment_source, receipt=None,
            dropped_event_count=_plain(dropped_event_count), assessed_at=assessed_at,
        )
        request = build_company_transaction_request(
            self.heads(), self._supervisor_authority(), transaction_id=transaction_id,
            command_id=command_id, events=[CompanyEventDraft(
                _telemetry_id(self._binding(), "coverage-event", transaction_id, coverage_surface),
                "provider.coverage.explicit", assessed_at, coverage, "AOI_verified",
            )],
        )
        committed = self.commit(request, recorded_at=assessed_at)
        return _coverage_result_from_record(committed.record, transaction_id, command_id, committed.idempotent_replay)

    def _telemetry_occurrences(
        self, adapter_instance_id: str, adapter_event_id: str,
    ) -> list[tuple[dict[str, Any], LedgerTransactionRecord]]:
        matches: list[tuple[dict[str, Any], LedgerTransactionRecord]] = []
        cursor = 0
        while True:
            records = self.records_after(cursor, limit=1024)
            if not records:
                return matches
            for record in records:
                for event in record.events:
                    payload = _plain(event.event["payload"])
                    if payload.get("contract_type") != PROVIDER_TELEMETRY_RECEIPT_V1:
                        continue
                    receipt = validate_provider_telemetry_receipt(payload)
                    if receipt["adapter_instance_id"] == adapter_instance_id and receipt["adapter_event_id"] == adapter_event_id:
                        matches.append((receipt, record))
            cursor = records[-1].global_sequence
            if len(records) < 1024:
                return matches

    def open_needs_user(
        self, question: str, *, item_id: str, origin_execution_id: str,
        expected_chief_term: int, expected_carrier_id: str, transaction_id: str,
        command_id: str, created_at: str,
    ) -> NeedsUserResult:
        """Open a durable question for the current logical Chief/user boundary."""
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _needs_user_result_from_record(durable, transaction_id, command_id, True)
        term, _carrier, _root = self._require_current_chief(expected_chief_term, expected_carrier_id)
        if self._needs_user_history(item_id):
            raise CompanyNeedsUserError("needs-user item already exists")
        blob = _needs_user_blob(self._state, question, NEEDS_USER_QUESTION_MEDIA_TYPE)
        revision = _needs_user_payload(
            self._binding(), item_id=item_id, revision=1, previous=ZERO_SHA256,
            origin_execution_id=origin_execution_id, opened_chief_term=term["term"],
            state="pending", question_blob=blob, answer_blob=None, created_at=created_at,
            updated_at=created_at, answered_at=None, answered_by_chief_term=None,
            answer_control_intent_id=None,
        )
        request = build_company_transaction_request(
            self.heads(), self._supervisor_authority(), transaction_id=transaction_id,
            command_id=command_id, events=[CompanyEventDraft(
                _telemetry_id(self._binding(), "needs-user-open", item_id),
                "needs_user.opened", created_at, revision, "AOI_verified",
            )],
        )
        result = self.commit(request, recorded_at=created_at)
        return _needs_user_result_from_record(result.record, transaction_id, command_id, result.idempotent_replay)

    def answer_needs_user(
        self, item_id: str, answer: str, *, expected_chief_term: int,
        expected_carrier_id: str, control_intent_id: str, receipt_id: str,
        transaction_id: str, command_id: str, answered_at: str,
    ) -> NeedsUserResult:
        """Append the terminal user answer; it is cooperative intent, not proof."""
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _needs_user_result_from_record(durable, transaction_id, command_id, True)
        term, _carrier, _root = self._require_current_chief(expected_chief_term, expected_carrier_id)
        history = self._needs_user_history(item_id)
        if len(history) != 1 or history[0]["state"] != "pending":
            raise CompanyNeedsUserError("needs-user item is not pending")
        first = history[0]
        if _parsed_time(answered_at) <= _parsed_time(first["created_at"]):
            raise CompanyNeedsUserError("needs-user answer time must advance")
        grant, _authority, chief_execution = self._current_chief_mutation_context()
        blob = _needs_user_blob(self._state, answer, NEEDS_USER_ANSWER_MEDIA_TYPE)
        revision = _needs_user_payload(
            self._binding(), item_id=item_id, revision=2, previous=first["revision_sha256"],
            origin_execution_id=first["origin_execution_id"], opened_chief_term=first["opened_chief_term"],
            state="answered", question_blob=first["question_blob"], answer_blob=blob,
            created_at=first["created_at"], updated_at=answered_at, answered_at=answered_at,
            answered_by_chief_term=term["term"], answer_control_intent_id=control_intent_id,
        )
        control = _needs_user_control_intent(
            self._binding(), grant=grant, execution_id=chief_execution["execution_id"],
            control_intent_id=control_intent_id, command_id=command_id, receipt_id=receipt_id,
            item_id=item_id, answer_sha256=revision["answer_sha256"], at=answered_at,
        )
        request = build_company_transaction_request(
            self.heads(), self._supervisor_authority(), transaction_id=transaction_id,
            command_id=command_id, events=[
                CompanyEventDraft(_telemetry_id(self._binding(), "needs-user-answer", item_id), "needs_user.answered", answered_at, revision, "AOI_verified"),
                CompanyEventDraft(_telemetry_id(self._binding(), "needs-user-intent", item_id), "control.needs_user_answer", answered_at, control, "AOI_verified"),
            ],
        )
        result = self.commit(request, recorded_at=answered_at)
        return _needs_user_result_from_record(result.record, transaction_id, command_id, result.idempotent_replay)

    def expire_needs_user(
        self, item_id: str, *, expected_chief_term: int, expected_carrier_id: str,
        transaction_id: str, command_id: str, expired_at: str,
    ) -> NeedsUserResult:
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _needs_user_result_from_record(durable, transaction_id, command_id, True)
        self._require_current_chief(expected_chief_term, expected_carrier_id)
        history = self._needs_user_history(item_id)
        if len(history) != 1 or history[0]["state"] != "pending":
            raise CompanyNeedsUserError("needs-user item is not pending")
        first = history[0]
        if _parsed_time(expired_at) <= _parsed_time(first["created_at"]):
            raise CompanyNeedsUserError("needs-user expiry time must advance")
        revision = _needs_user_payload(
            self._binding(), item_id=item_id, revision=2, previous=first["revision_sha256"],
            origin_execution_id=first["origin_execution_id"], opened_chief_term=first["opened_chief_term"],
            state="expired", question_blob=first["question_blob"], answer_blob=None,
            created_at=first["created_at"], updated_at=expired_at, answered_at=None,
            answered_by_chief_term=None, answer_control_intent_id=None,
        )
        request = build_company_transaction_request(
            self.heads(), self._supervisor_authority(), transaction_id=transaction_id,
            command_id=command_id, events=[CompanyEventDraft(
                _telemetry_id(self._binding(), "needs-user-expire", item_id), "needs_user.expired", expired_at, revision, "AOI_verified",
            )],
        )
        result = self.commit(request, recorded_at=expired_at)
        return _needs_user_result_from_record(result.record, transaction_id, command_id, result.idempotent_replay)

    def pending_needs_user(self, *, expected_chief_term: int, expected_carrier_id: str) -> tuple[dict[str, Any], ...]:
        self._require_current_chief(expected_chief_term, expected_carrier_id)
        pending: list[dict[str, Any]] = []
        for item in self.objects(contract_type=NEEDS_USER_REVISION_V1):
            revision = validate_needs_user_revision(_plain(item.payload))
            if revision["state"] != "pending":
                continue
            raw = self._state.blobs.read(revision["question_blob"]["sha256"])
            expected = canonical_company_json_bytes({"schema_version": 1, "content_type": "question", "text": json.loads(raw)["text"]})
            if raw != expected:
                raise CompanyNeedsUserError("needs-user question blob is not canonical")
            pending.append({"item_id": revision["item_id"], "origin_execution_id": revision["origin_execution_id"], "question": json.loads(raw)["text"], "created_at": revision["created_at"]})
        return tuple(sorted(pending, key=lambda value: value["item_id"]))

    def _require_current_chief(self, expected_term: int, expected_carrier_id: str) -> tuple[dict[str, Any], dict[str, Any], str]:
        try:
            term, carrier, root = self._current_chief_context()
        except CompanyChiefTakeoverError as exc:
            raise CompanyNeedsUserError("current Chief authority is unavailable") from exc
        if term["term"] != expected_term or carrier["carrier_id"] != expected_carrier_id:
            raise CompanyNeedsUserError("Chief term or carrier is fenced")
        if (
            carrier["state"] != "active"
            or carrier["session_availability"] != "available"
        ):
            raise CompanyNeedsUserError(
                "current Chief carrier is not available for mutation",
            )
        executions = [
            _plain(item.payload)
            for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if (
                item.payload["role"] == "chief"
                and item.payload["execution_kind"] == "carrier"
                and item.payload["carrier_id"] == carrier["carrier_id"]
                and item.payload["runtime_status"]
                in {"running", "telemetry_silent", "unknown"}
                and item.payload["engineering_status"]
                not in {"completed", "cancelled"}
            )
        ]
        if len(executions) != 1:
            raise CompanyNeedsUserError(
                "current Chief execution is not available for mutation",
            )
        return term, carrier, root

    def _needs_user_history(self, item_id: str) -> list[dict[str, Any]]:
        values = [validate_needs_user_revision(_plain(item.payload)) for item in self.objects(contract_type=NEEDS_USER_REVISION_V1) if item.payload["item_id"] == item_id]
        return sorted(values, key=lambda value: value["revision"])

    def _telemetry_replay(
        self, record: LedgerTransactionRecord, *, normalized: NormalizedTelemetry,
        adapter_instance_id: str, adapter_event_id: str, intake_sequence: int,
        transaction_id: str, command_id: str, received_at: str,
    ) -> ProviderTelemetryIngestResult:
        result = _telemetry_result_from_record(record, idempotent_replay=True)
        receipt = next(
            validate_provider_telemetry_receipt(_plain(event.event["payload"]))
            for event in record.events
            if _plain(event.event["payload"]).get("contract_type") == PROVIDER_TELEMETRY_RECEIPT_V1
        )
        if (
            result.transaction_id != transaction_id or result.command_id != command_id
            or receipt["provider"] != normalized.provider
            or receipt["source_class"] != normalized.source_class
            or receipt["adapter_instance_id"] != adapter_instance_id
            or receipt["adapter_event_id"] != adapter_event_id
            or receipt["intake_sequence"] != intake_sequence
            or receipt["received_at"] != received_at
            or receipt["raw_artifact"]["sha256"] != normalized.raw_sha256
            or receipt["raw_artifact"]["size_bytes"] != normalized.raw_size_bytes
        ):
            raise CompanyTelemetryIngestError("transaction replay differs from durable telemetry")
        return result

    def _last_adapter_sequence(
        self, provider: str, source_class: str, adapter_instance_id: str,
    ) -> int | None:
        values = [
            receipt["intake_sequence"]
            for receipt, _ in self._telemetry_occurrences_for_adapter(
                provider, source_class, adapter_instance_id,
            )
        ]
        return max(values) if values else None

    def _telemetry_occurrences_for_adapter(
        self, provider: str, source_class: str, adapter_instance_id: str,
    ) -> list[tuple[dict[str, Any], LedgerTransactionRecord]]:
        values: list[tuple[dict[str, Any], LedgerTransactionRecord]] = []
        cursor = 0
        while True:
            records = self.records_after(cursor, limit=1024)
            if not records:
                return values
            for record in records:
                for event in record.events:
                    payload = _plain(event.event["payload"])
                    if payload.get("contract_type") != PROVIDER_TELEMETRY_RECEIPT_V1:
                        continue
                    receipt = validate_provider_telemetry_receipt(payload)
                    if (
                        receipt["provider"] == provider
                        and receipt["source_class"] == source_class
                        and receipt["adapter_instance_id"] == adapter_instance_id
                    ):
                        values.append((receipt, record))
            cursor = records[-1].global_sequence
            if len(records) < 1024:
                return values

    def _latest_coverage(
        self, provider: str, source_class: str, adapter_instance_id: str, surface: str,
    ) -> dict[str, Any] | None:
        values: list[dict[str, Any]] = []
        cursor = 0
        while True:
            records = self.records_after(cursor, limit=1024)
            if not records:
                break
            for record in records:
                for event in record.events:
                    payload = _plain(event.event["payload"])
                    if payload.get("contract_type") != PROVIDER_COVERAGE_REVISION_V1:
                        continue
                    coverage = validate_provider_coverage_revision(payload)
                    if (
                        coverage["provider"] == provider
                        and coverage["source_class"] == source_class
                        and coverage["adapter_instance_id"] == adapter_instance_id
                        and coverage["coverage_surface"] == surface
                    ):
                        values.append(coverage)
            cursor = records[-1].global_sequence
            if len(records) < 1024:
                break
        return max(values, key=lambda value: value["revision"]) if values else None

    def _exact_telemetry_join(
        self, normalized: NormalizedTelemetry, *, registry_cursor: int,
    ) -> dict[str, Any]:
        """Join only an exact native ID already registered by AOI; never infer it."""

        try:
            return exact_provider_telemetry_join(
                provider=normalized.provider,
                facts=telemetry_facts_payload(normalized),
                executions=[
                    _plain(item.payload)
                    for item in self.objects(contract_type=EXECUTION_NODE_V1)
                ],
                dispatches=[
                    _plain(item.payload)
                    for item in self.objects(contract_type=DISPATCH_REQUEST_V1)
                ],
                registry_cursor=registry_cursor,
            )
        except TelemetryPolicyError as exc:
            raise CompanyTelemetryIngestError(str(exc)) from exc

    def _next_coverage_revision(
        self, *, provider: str, source_class: str, adapter_instance_id: str,
        surface: str, declared_event_kinds: Sequence[str], state: str, reason: str,
        assessment_source: str, receipt: Mapping[str, Any] | None,
        dropped_event_count: Mapping[str, Any], assessed_at: str,
    ) -> dict[str, Any]:
        if list(declared_event_kinds) != sorted(set(declared_event_kinds)):
            raise CompanyTelemetryIngestError("coverage event kinds must be sorted and unique")
        prior = self._latest_coverage(provider, source_class, adapter_instance_id, surface)
        if prior is not None and _parsed_time(assessed_at) <= _parsed_time(prior["assessed_at"]):
            raise CompanyTelemetryIngestError("coverage assessment time must advance")
        scope_id = _telemetry_id(self._binding(), "coverage-scope", provider, source_class, adapter_instance_id, surface)
        revision = 1 if prior is None else prior["revision"] + 1
        if state == "observed" and receipt is None:
            recent = self._telemetry_occurrences_for_adapter(provider, source_class, adapter_instance_id)
            receipt = max(
                (value[0] for value in recent),
                key=lambda value: (
                    _parsed_time(str(value["received_at"])),
                    str(value["receipt_id"]),
                ),
                default=None,
            )
        if state == "observed" and receipt is None:
            raise CompanyTelemetryIngestError("observed coverage requires a durable receipt")
        if state == "observed":
            reason = "observed"
            gap_started_at = None
            observation = {"state": "known", "reason": "observed"}
            dropped_event_count = {"value": 0, "source": "adapter_route", "quality": "observed", "reason": "observed"}
        elif state == "degraded":
            gap_started_at = (prior or {}).get("gap_started_at") or assessed_at
            observation = {"state": "known", "reason": "observed"}
        elif state == "unavailable":
            gap_started_at = None
            observation = {"state": "unavailable", "reason": reason}
        elif state == "unknown":
            gap_started_at = None
            observation = {"state": "unknown", "reason": reason}
        else:
            raise CompanyTelemetryIngestError("coverage state is invalid")
        payload = {
            "contract_type": PROVIDER_COVERAGE_REVISION_V1, "schema_version": 1,
            **self._binding(), "coverage_scope_id": scope_id,
            "coverage_surface": surface,
            "revision_id": _telemetry_id(self._binding(), "coverage-revision", scope_id, str(revision)),
            "revision": revision,
            "previous_revision_sha256": ZERO_SHA256 if prior is None else prior["coverage_sha256"],
            "provider": provider, "adapter_instance_id": adapter_instance_id,
            "source_class": source_class, "declared_event_kinds": list(declared_event_kinds),
            "state": state, "reason": reason, "assessment_source": assessment_source,
            "last_receipt_id": None if receipt is None else receipt["receipt_id"],
            "last_received_at": None if receipt is None else receipt["received_at"],
            "gap_started_at": gap_started_at,
            "dropped_event_count": dict(dropped_event_count), "assessed_at": assessed_at,
            "observation": observation, "coverage_sha256": ZERO_SHA256,
        }
        payload["coverage_sha256"] = company_contract_sha256({
            key: value for key, value in payload.items() if key != "coverage_sha256"
        })
        try:
            return validate_provider_coverage_revision(payload)
        except (TypeError, ValueError) as exc:
            raise CompanyTelemetryIngestError("coverage payload is invalid") from exc

    def _binding(self) -> dict[str, Any]:
        manifest = validate_company_manifest(self._state.resolved.manifest)
        return {
            "company_id": manifest["company_id"],
            "company_incarnation": manifest["company_incarnation"],
            "lock_domain_generation": manifest["lock_domain_generation"],
        }

    def _current_chief_context(
        self,
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        terms = [
            _plain(item.payload)
            for item in self.objects(contract_type=CHIEF_TERM_V1)
        ]
        if len(terms) != 1 or terms[0]["state"] != "active":
            raise CompanyChiefTakeoverError(
                "company lacks one active logical Chief term",
            )
        term = terms[0]
        carriers = {
            str(item.payload["carrier_id"]): _plain(item.payload)
            for item in self.objects(contract_type=CARRIER_BINDING_V1)
        }
        carrier = carriers.get(str(term["carrier_id"]))
        if (
            carrier is None
            or carrier["actor_id"] != term["chief_id"]
            or carrier["state"] == "fenced"
        ):
            raise CompanyChiefTakeoverError(
                "current Chief carrier differs from its term",
            )
        grants = [
            _plain(item.payload)
            for item in self.objects(contract_type=AUTHORITY_GRANT_V1)
            if (
                item.payload["actor_kind"] == "chief"
                and item.payload["actor_id"] == term["chief_id"]
                and item.payload["carrier_id"] == term["carrier_id"]
                and item.payload["term"] == term["term"]
                and item.payload["chief_epoch"] == term["epoch"]
                and item.payload["authority_state"] == "active"
                and "company.mutate" in item.payload["permissions"]
            )
        ]
        if len(grants) != 1:
            raise CompanyChiefTakeoverError(
                "current Chief authority grant is missing or ambiguous",
            )
        roots = [
            _plain(item.payload)
            for item in self.objects(contract_type=ORGANIZATION_NODE_V1)
            if (
                item.payload["role"] == "chief"
                and item.payload["parent_node_id"] is None
                and item.payload["reports_to_node_id"] is None
            )
        ]
        if len(roots) != 1:
            raise CompanyChiefTakeoverError(
                "company lacks one Chief organization root",
            )
        return term, carrier, str(roots[0]["node_id"])

    def _unknown_genesis_carrier_matches(
        self,
        carrier: Mapping[str, Any],
        *,
        chief_id: str,
        state: str,
    ) -> bool:
        """Recognize only the deterministic no-provider genesis placeholder."""

        manifest = validate_company_manifest(
            self._state.resolved.manifest,
        )
        binding = self._binding()
        ids = _genesis_ids(
            str(binding["company_id"]),
            int(binding["company_incarnation"]),
            int(binding["lock_domain_generation"]),
        )
        if chief_id != ids["chief"]:
            return False
        expected = _carrier_payload(
            binding,
            actor_id=ids["chief"],
            carrier_id=ids["chief_carrier"],
            bootstrap_at=str(manifest["created_at"]),
            known_carrier=None,
        )
        if state == "fenced":
            try:
                expected = validate_carrier_binding({
                    **expected,
                    "state": "fenced",
                })
            except ValueError:
                return False
        elif state != "unknown":
            return False
        return bool(_plain(carrier) == expected)

    def _supervisor_authority(self) -> dict[str, Any]:
        grants = [
            _plain(item.payload)
            for item in self.objects(contract_type=AUTHORITY_GRANT_V1)
            if (
                item.payload["actor_kind"] == "supervisor"
                and item.payload["authority_state"] == "active"
                and "company.mutate" in item.payload["permissions"]
            )
        ]
        if len(grants) != 1:
            raise CompanyChiefTakeoverError(
                "company lacks one active Supervisor authority grant",
            )
        try:
            return authority_from_grant(grants[0])
        except ValueError as exc:
            raise CompanyChiefTakeoverError(
                "Supervisor authority grant is invalid",
            ) from exc

    def _current_chief_mutation_context(
        self,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        term, carrier, _root = self._current_chief_context()
        if (
            carrier["state"] != "active"
            or carrier["session_availability"] != "available"
        ):
            raise CompanyDepartmentLifecycleError(
                "current Chief carrier is not available for mutation",
            )
        grants = [
            _plain(item.payload)
            for item in self.objects(contract_type=AUTHORITY_GRANT_V1)
            if (
                item.payload["actor_kind"] == "chief"
                and item.payload["actor_id"] == term["chief_id"]
                and item.payload["carrier_id"] == term["carrier_id"]
                and item.payload["term"] == term["term"]
                and item.payload["chief_epoch"] == term["epoch"]
                and item.payload["authority_state"] == "active"
                and "company.mutate" in item.payload["permissions"]
            )
        ]
        executions = [
            _plain(item.payload)
            for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if (
                item.payload["role"] == "chief"
                and item.payload["carrier_id"] == term["carrier_id"]
                and item.payload["runtime_status"]
                in {"running", "telemetry_silent", "unknown"}
                and item.payload["engineering_status"]
                not in {"completed", "cancelled"}
            )
        ]
        if len(grants) != 1 or len(executions) != 1:
            raise CompanyDepartmentLifecycleError(
                "department lifecycle requires one current Chief grant "
                "and execution",
            )
        try:
            authority = authority_from_grant(grants[0])
        except ValueError as exc:
            raise CompanyDepartmentLifecycleError(
                "current Chief grant is invalid",
            ) from exc
        return grants[0], authority, executions[0]

    def _require_exact_chief_dispatch_fence(
        self,
        *,
        chief_id: str,
        carrier_id: str,
        term: int,
        epoch: int,
        chief_execution_id: str,
    ) -> None:
        """Fence a new queue write to the one currently running Chief."""

        current_term, current_carrier, _root = self._current_chief_context()
        _grant, _authority, execution = self._current_chief_mutation_context()
        if (
            current_term["chief_id"] != chief_id
            or current_term["carrier_id"] != carrier_id
            or current_term["term"] != term
            or current_term["epoch"] != epoch
            or current_carrier["carrier_id"] != carrier_id
            or execution["execution_id"] != chief_execution_id
        ):
            raise CompanyDepartmentLifecycleError(
                "department dispatch Chief fence is stale",
            )

    def _department_context(
        self,
        department_id: str,
    ) -> tuple[
        ProjectedObject,
        ProjectedObject,
        ProjectedObject,
        ProjectedObject | None,
    ]:
        identities = [
            item
            for item in self.objects(contract_type=DEPARTMENT_IDENTITY_V1)
            if item.payload["department_id"] == department_id
        ]
        snapshots = [
            item
            for item in self.objects(contract_type=DEPARTMENT_SNAPSHOT_V1)
            if item.payload["department_id"] == department_id
        ]
        if len(identities) != 1 or len(snapshots) != 1:
            raise CompanyDepartmentLifecycleError(
                "department identity or snapshot is missing",
            )
        identity = identities[0]
        lead_node_id = identity.payload["lead_node_id"]
        if not isinstance(lead_node_id, str):
            raise CompanyDepartmentLifecycleError(
                "department has no stable lead identity",
            )
        leads = [
            item
            for item in self.objects(contract_type=ORGANIZATION_NODE_V1)
            if item.payload["node_id"] == lead_node_id
        ]
        if len(leads) != 1:
            raise CompanyDepartmentLifecycleError(
                "department lead organization node is missing",
            )
        carriers = [
            item
            for item in self.objects(contract_type=CARRIER_BINDING_V1)
            if (
                item.payload["actor_id"] == lead_node_id
                and item.payload["state"] in {
                    "active", "parked", "unknown",
                }
            )
        ]
        if len(carriers) > 1:
            raise CompanyDepartmentLifecycleError(
                "department lead has multiple current carriers",
            )
        return (
            identity,
            leads[0],
            snapshots[0],
            None if not carriers else carriers[0],
        )

    def park_department(
        self,
        department_id: str,
        snapshot_document: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        requested_at: str,
        recorded_at: str,
        trigger: str = "explicit",
    ) -> DepartmentLifecycleResult:
        """Durably checkpoint and park one idle department."""

        binding = self._binding()
        try:
            normalized_document = validate_department_snapshot_document(
                snapshot_document,
            )
        except ValueError as exc:
            raise CompanyDepartmentLifecycleError(
                "department snapshot document is invalid",
            ) from exc
        named_reference_fields = (
            "charter_ref",
            "constraints_ref",
            "decisions_ref",
            "dissent_ref",
            "open_questions_ref",
            "blockers_ref",
            "risks_ref",
            "backlog_ref",
            "handoff_ref",
        )
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            self._verify_available_blob_refs(
                [
                    *(
                        normalized_document[field]
                        for field in named_reference_fields
                    ),
                    *normalized_document["artifact_refs"],
                ],
                label="department snapshot member",
            )
            raw_document = canonical_company_json_bytes(
                normalized_document,
            )
            try:
                metadata = self._state.blobs.metadata(
                    company_contract_sha256(normalized_document),
                )
            except (BlobStoreError, OSError) as exc:
                raise CompanyDepartmentLifecycleError(
                    "durable department snapshot document is missing",
                ) from exc
            if metadata.size_bytes != len(raw_document):
                raise CompanyDepartmentLifecycleError(
                    "durable department snapshot document size differs",
                )
            return _department_lifecycle_replay(
                durable,
                operation="park",
                department_id=department_id,
                command_id=command_id,
                requested_at=requested_at,
                recorded_at=recorded_at,
                trigger=trigger,
                snapshot_document_sha256=company_contract_sha256(
                    normalized_document,
                ),
            )
        identity_item, lead_item, snapshot_item, carrier_item = (
            self._department_context(department_id)
        )
        grant, authority, chief_execution = (
            self._current_chief_mutation_context()
        )
        heads = self.heads()
        next_cursor = heads.global_head.global_sequence + 1
        document = normalized_document
        if (
            {
                key: document[key]
                for key in (
                    "company_id",
                    "company_incarnation",
                    "lock_domain_generation",
                )
            }
            != binding
            or document["department_id"] != department_id
            or document["lead_node_id"] != lead_item.payload["node_id"]
            or document["revision"] != snapshot_item.payload["revision"] + 1
            or document["previous_snapshot_id"]
            != snapshot_item.payload["snapshot_id"]
            or len(snapshot_item.payload["artifact_refs"]) != 1
            or document["previous_document_sha256"]
            != snapshot_item.payload["artifact_refs"][0]["sha256"]
            or document["company_cursor"] != next_cursor
            or document["captured_at"] != recorded_at
            or document["capture_reason"] != "park"
        ):
            raise CompanyDepartmentLifecycleError(
                "department snapshot document differs from current state",
            )
        raw_document = canonical_company_json_bytes(document)
        metadata = self._state.blobs.put(raw_document)
        snapshot_ref = {
            "contract_type": BLOB_REF_V1,
            "schema_version": 1,
            "sha256": metadata.sha256,
            "size_bytes": metadata.size_bytes,
            "media_type": DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
            "availability": "available",
        }
        ids = _department_lifecycle_ids(
            binding,
            operation="park",
            department_id=department_id,
            transaction_id=transaction_id,
            command_id=command_id,
        )
        identity = _plain(identity_item.payload)
        lead = _plain(lead_item.payload)
        old_snapshot = _plain(snapshot_item.payload)
        parked_identity = {
            **identity,
            "status": "parked",
            "observation": {"state": "known", "reason": "observed"},
        }
        parked_lead = {
            **lead,
            "status": "parked",
            "observation": {"state": "known", "reason": "observed"},
        }
        new_snapshot = {
            "contract_type": DEPARTMENT_SNAPSHOT_V1,
            "schema_version": 1,
            **binding,
            "snapshot_id": document["snapshot_id"],
            "department_id": department_id,
            "revision": document["revision"],
            "company_cursor": next_cursor,
            "previous_snapshot_id": old_snapshot["snapshot_id"],
            "charter_sha256": document["charter_ref"]["sha256"],
            "constraints_sha256": document["constraints_ref"]["sha256"],
            "decisions_sha256": document["decisions_ref"]["sha256"],
            "open_questions_sha256":
                document["open_questions_ref"]["sha256"],
            "handoff_sha256": document["handoff_ref"]["sha256"],
            "artifact_refs": [snapshot_ref],
            "captured_at": recorded_at,
            "observation": {"state": "known", "reason": "observed"},
        }
        parked_carrier: dict[str, Any] | None = None
        if carrier_item is not None and carrier_item.payload["state"] in {
            "active", "unknown",
        }:
            carrier_id = str(carrier_item.payload["carrier_id"])
            executions = [
                item
                for item in self.objects(contract_type=EXECUTION_NODE_V1)
                if item.payload["carrier_id"] == carrier_id
            ]
            if (
                not executions
                or any(
                    not self._department_execution_is_park_ready(
                        item.payload,
                    )
                    for item in executions
                )
            ):
                raise CompanyDepartmentLifecycleError(
                    "department carrier lacks provider-confirmed stopped "
                    "execution evidence",
                )
            parked_carrier = {
                **_plain(carrier_item.payload),
                "session_id": None,
                "session_availability": "unavailable",
                "state": "parked",
                "last_observed_at": recorded_at,
                "observation": {"state": "known", "reason": "observed"},
            }
        lifecycle_request = _department_lifecycle_request(
            binding,
            operation="park",
            trigger=trigger,
            requested_at=requested_at,
            identity_item=identity_item,
            lead_item=lead_item,
            snapshot_item=snapshot_item,
            carrier_item=carrier_item,
            scope_sha256=_department_scope_sha256(
                department_id,
                snapshot_item,
            ),
            heads=heads,
            snapshot_document=snapshot_ref,
        )
        lifecycle_result = {
            "result_type": "department_lifecycle_result_v1",
            "schema_version": 1,
            **binding,
            "operation": "park",
            "transaction_id": transaction_id,
            "command_id": command_id,
            "committed_cursor": next_cursor,
            "department_id": department_id,
            "lead_node_id": lead["node_id"],
            "lifecycle_state": "parked",
            "department_status": "parked",
            "lead_status": "parked",
            "snapshot_id": new_snapshot["snapshot_id"],
            "snapshot_revision": new_snapshot["revision"],
            "snapshot_payload_sha256":
                company_contract_sha256(new_snapshot),
            "snapshot_cursor": next_cursor,
            "carrier_transition":
                "parked" if parked_carrier is not None else "none",
            "carrier_id":
                None if parked_carrier is None
                else parked_carrier["carrier_id"],
            "carrier_state":
                None if parked_carrier is None else "parked",
            "replaced_carrier_id": None,
            "dispatch_request_id": None,
            "dispatch_revision": None,
            "dispatch_state": None,
            "execution_id": None,
            "runtime_effect": "none",
        }
        intent = _department_control_intent(
            binding,
            ids=ids,
            command_id=command_id,
            execution_id=str(chief_execution["execution_id"]),
            grant=grant,
            request=lifecycle_request,
            result=lifecycle_result,
            transaction_id=transaction_id,
            created_at=requested_at,
            terminal_at=recorded_at,
        )
        drafts = [
            CompanyEventDraft(
                event_id=ids["snapshot_event"],
                event_type="department.snapshot.recorded",
                recorded_at=recorded_at,
                payload=new_snapshot,
            ),
            CompanyEventDraft(
                event_id=ids["lead_event"],
                event_type="department.organization.parked",
                recorded_at=recorded_at,
                payload=parked_lead,
            ),
            CompanyEventDraft(
                event_id=ids["identity_event"],
                event_type="department.identity.parked",
                recorded_at=recorded_at,
                payload=parked_identity,
            ),
        ]
        if parked_carrier is not None:
            drafts.append(CompanyEventDraft(
                event_id=ids["carrier_event"],
                event_type="department.carrier.parked",
                recorded_at=recorded_at,
                payload=parked_carrier,
            ))
        drafts.append(CompanyEventDraft(
            event_id=ids["intent_event"],
            event_type="department.park.intent.committed",
            recorded_at=recorded_at,
            payload=intent,
        ))
        request = build_company_transaction_request(
            heads,
            authority,
            transaction_id=transaction_id,
            command_id=command_id,
            events=drafts,
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _department_lifecycle_result(
            committed,
            lifecycle_result,
        )

    def resume_department(
        self,
        department_id: str,
        *,
        transaction_id: str,
        command_id: str,
        dispatch_request_id: str,
        reservation_id: str,
        task_id: str,
        packet_id: str,
        route_policy_id: str,
        requested_role: str,
        requested_capability_tier: str,
        requested_at: str,
        recorded_at: str,
    ) -> DepartmentLifecycleResult:
        """Wake a parked durable department and enqueue its lead."""

        return self._enqueue_department(
            department_id,
            operation="resume",
            transaction_id=transaction_id,
            command_id=command_id,
            dispatch_request_id=dispatch_request_id,
            reservation_id=reservation_id,
            task_id=task_id,
            packet_id=packet_id,
            route_policy_id=route_policy_id,
            requested_role=requested_role,
            requested_capability_tier=requested_capability_tier,
            requested_at=requested_at,
            recorded_at=recorded_at,
        )

    def enqueue_department_dispatch(
        self,
        department_id: str,
        *,
        transaction_id: str,
        command_id: str,
        dispatch_request_id: str,
        reservation_id: str,
        task_id: str,
        packet_id: str,
        route_policy_id: str,
        requested_role: str,
        requested_capability_tier: str,
        requested_at: str,
        recorded_at: str,
    ) -> DepartmentLifecycleResult:
        """Queue work and lazily wake the durable lead when parked."""

        return self._enqueue_department(
            department_id,
            operation="enqueue",
            transaction_id=transaction_id,
            command_id=command_id,
            dispatch_request_id=dispatch_request_id,
            reservation_id=reservation_id,
            task_id=task_id,
            packet_id=packet_id,
            route_policy_id=route_policy_id,
            requested_role=requested_role,
            requested_capability_tier=requested_capability_tier,
            requested_at=requested_at,
            recorded_at=recorded_at,
        )

    def enqueue_department_dispatch_fenced(
        self,
        department_id: str,
        *,
        chief_id: str,
        carrier_id: str,
        term: int,
        epoch: int,
        chief_execution_id: str,
        transaction_id: str,
        command_id: str,
        dispatch_request_id: str,
        reservation_id: str,
        task_id: str,
        packet_id: str,
        route_policy_id: str,
        requested_role: str,
        requested_capability_tier: str,
        requested_at: str,
        recorded_at: str,
    ) -> DepartmentLifecycleResult:
        """Enqueue under an exact current-Chief fence, preserving retries."""

        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            _require_durable_department_dispatch_chief_fence(
                durable,
                chief_id=chief_id,
                carrier_id=carrier_id,
                term=term,
                epoch=epoch,
                chief_execution_id=chief_execution_id,
            )
            requested_at, recorded_at = _department_lifecycle_replay_times(
                durable,
            )
        else:
            self._require_exact_chief_dispatch_fence(
                chief_id=chief_id,
                carrier_id=carrier_id,
                term=term,
                epoch=epoch,
                chief_execution_id=chief_execution_id,
            )
        return self.enqueue_department_dispatch(
            department_id,
            transaction_id=transaction_id,
            command_id=command_id,
            dispatch_request_id=dispatch_request_id,
            reservation_id=reservation_id,
            task_id=task_id,
            packet_id=packet_id,
            route_policy_id=route_policy_id,
            requested_role=requested_role,
            requested_capability_tier=requested_capability_tier,
            requested_at=requested_at,
            recorded_at=recorded_at,
        )

    def _enqueue_department(
        self,
        department_id: str,
        *,
        operation: str,
        transaction_id: str,
        command_id: str,
        dispatch_request_id: str,
        reservation_id: str,
        task_id: str,
        packet_id: str,
        route_policy_id: str,
        requested_role: str,
        requested_capability_tier: str,
        requested_at: str,
        recorded_at: str,
    ) -> DepartmentLifecycleResult:
        binding = self._binding()
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _department_lifecycle_replay(
                durable,
                operation=operation,
                department_id=department_id,
                command_id=command_id,
                requested_at=requested_at,
                recorded_at=recorded_at,
                dispatch_request_id=dispatch_request_id,
                reservation_id=reservation_id,
                task_id=task_id,
                packet_id=packet_id,
                route_policy_id=route_policy_id,
                requested_role=requested_role,
                requested_capability_tier=requested_capability_tier,
            )
        identity_item, lead_item, snapshot_item, carrier_item = (
            self._department_context(department_id)
        )
        old_status = str(identity_item.payload["status"])
        if operation == "resume" and old_status != "parked":
            raise CompanyDepartmentLifecycleError(
                "resume requires a parked department",
            )
        trigger = (
            "lazy_wake"
            if operation == "enqueue" and old_status == "parked"
            else "explicit"
        )
        grant, authority, chief_execution = (
            self._current_chief_mutation_context()
        )
        heads = self.heads()
        ids = _department_lifecycle_ids(
            binding,
            operation=operation,
            department_id=department_id,
            transaction_id=transaction_id,
            command_id=command_id,
        )
        task_candidates = [
            item
            for item in self.objects(contract_type=TASK_REVISION_V1)
            if item.payload["task_id"] == task_id
        ]
        packet_candidates = [
            item
            for item in self.objects(contract_type=WORK_PACKET_V1)
            if item.payload["packet_id"] == packet_id
        ]
        if len(packet_candidates) > 1:
            raise CompanyWorkDefinitionError(
                "dispatch work packet identity is ambiguous",
            )
        registered_task = None
        registered_packet = (
            None
            if not packet_candidates
            else _plain(packet_candidates[0].payload)
        )
        lifecycle_scope_sha256 = _department_scope_sha256(
            department_id,
            snapshot_item,
        )
        if registered_packet is not None:
            exact_tasks = [
                item
                for item in task_candidates
                if item.payload["task_revision_id"]
                == registered_packet["task_revision_id"]
            ]
            if (
                len(exact_tasks) != 1
                or registered_packet["task_id"] != task_id
            ):
                raise CompanyWorkDefinitionError(
                    "dispatch task and packet registration differ",
                )
            registered_task = _plain(exact_tasks[0].payload)
        elif task_candidates:
            raise CompanyWorkDefinitionError(
                "dispatch names a registered task without its packet",
            )
        enforcement_active = bool(
            self.objects(contract_type=WORK_DEFINITION_ENFORCEMENT_V1),
        )
        if enforcement_active and registered_packet is None:
            raise CompanyWorkDefinitionError(
                "registered work enforcement rejects an unbound queue item",
            )
        if registered_packet is not None:
            assert registered_task is not None
            if (
                tuple(
                    registered_packet[name]
                    for name in (
                        "department_id",
                        "target_node_id",
                        "manager_node_id",
                        "parent_execution_id",
                        "delegation_depth",
                    )
                )
                != (
                    department_id,
                    lead_item.payload["node_id"],
                    lead_item.payload["parent_node_id"],
                    chief_execution["execution_id"],
                    1,
                )
                or registered_packet["task_sha256"]
                != registered_task["task_sha256"]
                or _parsed_time(str(registered_packet["expires_at"]))
                <= _parsed_time(recorded_at)
            ):
                raise CompanyWorkDefinitionError(
                    "registered work packet differs from department routing",
                )
            dispatch_scope_sha256 = company_contract_sha256(
                registered_packet["authority_scope"],
            )
        else:
            dispatch_scope_sha256 = lifecycle_scope_sha256
        lifecycle_request = _department_lifecycle_request(
            binding,
            operation=operation,
            trigger=trigger,
            requested_at=requested_at,
            identity_item=identity_item,
            lead_item=lead_item,
            snapshot_item=snapshot_item,
            carrier_item=carrier_item,
            scope_sha256=lifecycle_scope_sha256,
            heads=heads,
            dispatch_request_id=dispatch_request_id,
            reservation_id=reservation_id,
            task_id=task_id,
            packet_id=packet_id,
            route_policy_id=route_policy_id,
            requested_role=requested_role,
            requested_capability_tier=requested_capability_tier,
        )
        dispatch = validate_dispatch_request({
            "contract_type": DISPATCH_REQUEST_V1,
            "schema_version": 1,
            **binding,
            "dispatch_request_id": dispatch_request_id,
            "dispatch_revision_id": ids["dispatch_revision"],
            "revision": 1,
            "previous_event_id": None,
            "previous_payload_sha256": None,
            "command_id": command_id,
            "reservation_id": reservation_id,
            "task_id": task_id,
            "packet_id": packet_id,
            "manager_node_id": lead_item.payload["parent_node_id"],
            "target_node_id": lead_item.payload["node_id"],
            "department_id": department_id,
            "parent_execution_id": chief_execution["execution_id"],
            "requested_role": requested_role,
            "requested_capability_tier": requested_capability_tier,
            "route_policy_id": route_policy_id,
            "scope_sha256": dispatch_scope_sha256,
            "delegation_depth": 1,
            "state": "queued",
            "attempt": 0,
            "provider_dispatch_id": None,
            "execution_id": None,
            "effect_evidence": [],
            "reconcile_ref": None,
            "resolves_event_ids": [],
            "created_at": recorded_at,
            "updated_at": recorded_at,
            "provenance": "AOI_verified",
            "observation": {"state": "known", "reason": "observed"},
        })
        work_dispatch_binding = None
        if registered_packet is not None:
            assert registered_task is not None
            binding_unsigned = {
                "contract_type": WORK_DISPATCH_BINDING_V1,
                "schema_version": 1,
                **binding,
                "binding_id": _work_definition_id(
                    binding,
                    "dispatch-binding",
                    dispatch_request_id,
                ),
                "transaction_id": transaction_id,
                "command_id": command_id,
                "dispatch_request_id": dispatch_request_id,
                "dispatch_revision_id": dispatch["dispatch_revision_id"],
                "dispatch_payload_sha256":
                    company_contract_sha256(dispatch),
                "task_id": registered_task["task_id"],
                "task_revision_id":
                    registered_task["task_revision_id"],
                "task_sha256": registered_task["task_sha256"],
                "packet_id": registered_packet["packet_id"],
                "packet_sha256": registered_packet["packet_sha256"],
                "prompt_ref": _plain(registered_packet["prompt_ref"]),
                "context_manifest_ref":
                    _plain(registered_packet["context_manifest_ref"]),
                "department_id": department_id,
                "target_node_id": lead_item.payload["node_id"],
                "manager_node_id": lead_item.payload["parent_node_id"],
                "parent_execution_id": chief_execution["execution_id"],
                "delegation_depth":
                    registered_packet["delegation_depth"],
                "authority_scope_sha256": dispatch_scope_sha256,
                "provider_allowlist":
                    _plain(
                        registered_packet["authority_scope"][
                            "provider_allowlist"
                        ],
                    ),
                "expires_at": registered_packet["expires_at"],
                "created_at": recorded_at,
                "provenance": "AOI_verified",
                "observation": {"state": "known", "reason": "observed"},
            }
            try:
                work_dispatch_binding = validate_work_dispatch_binding({
                    **binding_unsigned,
                    "binding_sha256":
                        company_contract_sha256(binding_unsigned),
                })
            except ValueError as exc:
                raise CompanyWorkDefinitionError(
                    "work dispatch binding is invalid",
                ) from exc
        lifecycle_result = validate_department_lifecycle_result({
            "result_type": "department_lifecycle_result_v1",
            "schema_version": 1,
            **binding,
            "operation": operation,
            "transaction_id": transaction_id,
            "command_id": command_id,
            "committed_cursor":
                heads.global_head.global_sequence + 1,
            "department_id": department_id,
            "lead_node_id": lead_item.payload["node_id"],
            "lifecycle_state":
                "waking" if old_status == "parked" else "active",
            "department_status": "active",
            "lead_status": "active",
            "snapshot_id": snapshot_item.payload["snapshot_id"],
            "snapshot_revision": snapshot_item.payload["revision"],
            "snapshot_payload_sha256":
                company_contract_sha256(_plain(snapshot_item.payload)),
            "snapshot_cursor": snapshot_item.payload["company_cursor"],
            "carrier_transition": "pending",
            "carrier_id":
                None if carrier_item is None
                else carrier_item.payload["carrier_id"],
            "carrier_state":
                None if carrier_item is None
                else carrier_item.payload["state"],
            "replaced_carrier_id": None,
            "dispatch_request_id": dispatch_request_id,
            "dispatch_revision": 1,
            "dispatch_state": "queued",
            "execution_id": None,
            "runtime_effect": "pending_dispatch",
        }, request=lifecycle_request)
        intent = _department_control_intent(
            binding,
            ids=ids,
            command_id=command_id,
            execution_id=str(chief_execution["execution_id"]),
            grant=grant,
            request=lifecycle_request,
            result=lifecycle_result,
            transaction_id=transaction_id,
            created_at=requested_at,
            terminal_at=recorded_at,
        )
        drafts: list[CompanyEventDraft] = []
        if old_status == "parked":
            drafts.extend((
                CompanyEventDraft(
                    event_id=ids["lead_event"],
                    event_type="department.organization.activated",
                    recorded_at=recorded_at,
                    payload={
                        **_plain(lead_item.payload),
                        "status": "active",
                        "observation": {
                            "state": "known",
                            "reason": "observed",
                        },
                    },
                ),
                CompanyEventDraft(
                    event_id=ids["identity_event"],
                    event_type="department.identity.activated",
                    recorded_at=recorded_at,
                    payload={
                        **_plain(identity_item.payload),
                        "status": "active",
                        "observation": {
                            "state": "known",
                            "reason": "observed",
                        },
                    },
                ),
            ))
        drafts.append(
            CompanyEventDraft(
                event_id=ids["dispatch_event"],
                event_type="dispatch.request.queued",
                recorded_at=recorded_at,
                payload=dispatch,
            ),
        )
        if work_dispatch_binding is not None:
            drafts.append(CompanyEventDraft(
                event_id=_work_definition_id(
                    binding,
                    "dispatch-binding-event",
                    transaction_id,
                ),
                event_type="work.dispatch.bound",
                recorded_at=recorded_at,
                payload=work_dispatch_binding,
                provenance="AOI_verified",
            ))
        drafts.append(
            CompanyEventDraft(
                event_id=ids["intent_event"],
                event_type=(
                    "department.resume.intent.committed"
                    if operation == "resume"
                    else "department.dispatch.intent.committed"
                ),
                recorded_at=recorded_at,
                payload=intent,
            ),
        )
        request = build_company_transaction_request(
            heads,
            authority,
            transaction_id=transaction_id,
            command_id=command_id,
            events=drafts,
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _department_lifecycle_result(committed, lifecycle_result)

    def admit_department_dispatch(
        self,
        dispatch_request_id: str,
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> DepartmentDispatchResult:
        """Reserve company/fanout capacity for one queued department lead."""

        if self._state.record_by_transaction_id(transaction_id) is None:
            self._assert_department_dispatch_admission_available(
                dispatch_request_id,
            )
        return self._transition_department_dispatch(
            dispatch_request_id,
            target_state="admitted",
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            provenance="AOI_verified",
            observation={"state": "known", "reason": "observed"},
        )

    def admit_department_dispatch_resident(
        self,
        dispatch_request_id: str,
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> DepartmentDispatchResult:
        """Admit a durable authorized queue item, including exact replays."""

        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            recorded_at = _department_dispatch_replay_time(durable)
        return self.admit_department_dispatch(
            dispatch_request_id,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
        )

    def _assert_department_dispatch_admission_available(
        self,
        dispatch_request_id: str,
    ) -> None:
        """Return a typed queue reason before attempting an invariant commit."""

        current = self._current_department_dispatch(dispatch_request_id)
        if current.payload["state"] != "queued":
            return
        snapshot = self._state.query_snapshot()
        try:
            projection = reduce_company_invariants(
                tuple(
                    InvariantObject(
                        item.contract_type,
                        item.object_key,
                        item.event_id,
                        item.global_sequence,
                        company_contract_sha256(_plain(item.payload)),
                        _plain(item.payload),
                    )
                    for item in snapshot.objects
                ),
                snapshot.uncertain_dispatches,
            )
        except Exception as exc:
            raise CompanyDepartmentLifecycleError(
                "department dispatch admission projection is invalid",
            ) from exc
        if (
            projection.unattributed_active
            or not projection.manager_capacity_complete
        ):
            raise CompanyDepartmentDispatchCapacityBlocked("unattributed")
        if projection.company_capacity >= MAX_ACTIVE_CARRIERS:
            raise CompanyDepartmentDispatchCapacityBlocked("capacity")
        manager_capacity = dict(projection.manager_capacity)
        manager_id = str(current.payload["manager_node_id"])
        if manager_capacity.get(manager_id, 0) >= MAX_MANAGER_ACTIVE_FANOUT:
            raise CompanyDepartmentDispatchCapacityBlocked("fanout")

    def begin_department_dispatch(
        self,
        dispatch_request_id: str,
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> DepartmentDispatchResult:
        """Record that the provider launch request has begun."""

        if (
            self._state.record_by_transaction_id(transaction_id) is None
            and self.objects(contract_type=WORK_DEFINITION_ENFORCEMENT_V1)
        ):
            current = self._current_department_dispatch(
                dispatch_request_id,
            )
            work_bindings = [
                item
                for item in self.objects(
                    contract_type=WORK_DISPATCH_BINDING_V1,
                )
                if item.payload["dispatch_request_id"]
                == dispatch_request_id
            ]
            if (
                len(work_bindings) != 1
                or current.payload["state"] != "admitted"
                or _parsed_time(
                    str(work_bindings[0].payload["expires_at"]),
                )
                <= _parsed_time(recorded_at)
            ):
                raise CompanyWorkDefinitionError(
                    "registered launch gate rejects this dispatch",
                )
        return self._transition_department_dispatch(
            dispatch_request_id,
            target_state="in_flight",
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            provenance="AOI_verified",
            observation={"state": "known", "reason": "observed"},
        )

    def fail_department_dispatch(
        self,
        dispatch_request_id: str,
        provider_receipt: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> DepartmentDispatchResult:
        """Record a provider-grade, known dispatch failure."""

        return self._transition_department_dispatch(
            dispatch_request_id,
            target_state="failed_known",
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            provider_receipt=provider_receipt,
        )

    def mark_department_dispatch_effect_unknown(
        self,
        dispatch_request_id: str,
        provider_receipt: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> DepartmentDispatchResult:
        """Freeze a transport-ambiguous launch without inventing a worker."""

        return self._transition_department_dispatch(
            dispatch_request_id,
            target_state="effect_unknown",
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            provider_receipt=provider_receipt,
            receipt_state="effect_unknown",
        )

    def _transition_department_dispatch(
        self,
        dispatch_request_id: str,
        *,
        target_state: str,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
        provenance: str = "AOI_verified",
        observation: Mapping[str, Any] | None = None,
        provider_receipt: Mapping[str, Any] | None = None,
        receipt_state: str = "committed",
    ) -> DepartmentDispatchResult:
        if observation is None:
            observation = {"state": "known", "reason": "observed"}
        expected_receipt_kind = {
            "failed_known": "dispatch_failed",
            "effect_unknown": "dispatch_effect_unknown",
        }.get(target_state)
        receipt: dict[str, Any] | None = None
        if expected_receipt_kind is not None:
            if provider_receipt is None:
                raise CompanyDepartmentLifecycleError(
                    "terminal dispatch requires a typed provider receipt",
                )
            receipt = self._provider_lifecycle_receipt(
                provider_receipt,
                event_kind=expected_receipt_kind,
                transaction_id=transaction_id,
                command_id=command_id,
                recorded_at=recorded_at,
            )
            provenance = str(receipt["provenance"])
            observation = receipt["observation"]
            effect_evidence = [receipt["raw_artifact"]]
            reconcile_ref = receipt["reconcile_ref"]
        else:
            if provider_receipt is not None:
                raise CompanyDepartmentLifecycleError(
                    "local dispatch transition cannot use provider evidence",
                )
            effect_evidence = []
            reconcile_ref = None
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _department_dispatch_replay(
                durable,
                dispatch_request_id=dispatch_request_id,
                target_state=target_state,
                command_id=command_id,
                recorded_at=recorded_at,
                effect_evidence=effect_evidence,
                reconcile_ref=reconcile_ref,
                provenance=provenance,
                observation=observation,
                receipt_state=receipt_state,
                provider_receipt=receipt,
            )
        current = self._current_department_dispatch(dispatch_request_id)
        allowed_previous = {
            "admitted": "queued",
            "in_flight": "admitted",
            "failed_known": "in_flight",
            "effect_unknown": "in_flight",
        }
        if (
            target_state not in allowed_previous
            or current.payload["state"] != allowed_previous[target_state]
        ):
            raise CompanyDepartmentLifecycleError(
                "department dispatch state transition is invalid",
            )
        if target_state in {"failed_known", "effect_unknown"}:
            if provenance not in _PROVIDER_GRADE_PROVENANCE:
                raise CompanyDepartmentLifecycleError(
                    "terminal dispatch observation is not provider grade",
                )
        elif (
            effect_evidence
            or reconcile_ref is not None
            or provenance != "AOI_verified"
            or dict(observation) != {
                "state": "known",
                "reason": "observed",
            }
        ):
            raise CompanyDepartmentLifecycleError(
                "automatic dispatch transition claims unsupported evidence",
            )
        payload = _next_department_dispatch_payload(
            current,
            target_state=target_state,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            effect_evidence=effect_evidence,
            reconcile_ref=reconcile_ref,
            provenance=provenance,
            observation=observation,
        )
        if receipt is not None and (
            receipt["dispatch_request_id"] != dispatch_request_id
            or receipt["dispatch_revision"] != payload["revision"]
            or receipt["dispatch_revision_id"]
            != payload["dispatch_revision_id"]
            or receipt["organization_node_id"] != payload["target_node_id"]
        ):
            raise CompanyDepartmentLifecycleError(
                "provider receipt differs from the dispatch revision",
            )
        event_id = _department_dispatch_event_id(
            payload,
            transaction_id=transaction_id,
        )
        drafts = (
            [
                *_provider_lifecycle_drafts(receipt),
                CompanyEventDraft(
                    event_id=event_id,
                    event_type=f"dispatch.request.{target_state}",
                    recorded_at=recorded_at,
                    payload=payload,
                    provenance=provenance,
                ),
            ]
            if receipt is not None
            else [CompanyEventDraft(
                event_id=event_id,
                event_type=f"dispatch.request.{target_state}",
                recorded_at=recorded_at,
                payload=payload,
                provenance=provenance,
            )]
        )
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=drafts,
        )
        committed = self.commit(
            request,
            state=receipt_state,
            recorded_at=recorded_at,
        )
        return _department_dispatch_result(
            committed.record,
            payload,
            idempotent_replay=committed.idempotent_replay,
        )

    def dispatch_department_lead(
        self,
        dispatch_request_id: str,
        provider_receipt: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> DepartmentDispatchResult:
        """Bind a provider-observed carrier and fresh lead execution."""

        receipt = self._provider_lifecycle_receipt(
            provider_receipt,
            event_kind="dispatch_succeeded",
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
        )
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _department_dispatch_success_replay(
                durable,
                dispatch_request_id=dispatch_request_id,
                provider_receipt=receipt,
                command_id=command_id,
                recorded_at=recorded_at,
            )
        current = self._current_department_dispatch(dispatch_request_id)
        if current.payload["state"] != "in_flight":
            raise CompanyDepartmentLifecycleError(
                "known dispatch success requires an in-flight request",
            )
        department_id = current.payload["department_id"]
        if not isinstance(department_id, str):
            raise CompanyDepartmentLifecycleError(
                "dispatch request is not owned by a department",
            )
        identity_item, lead_item, _snapshot_item, carrier_item = (
            self._department_context(department_id)
        )
        parent_executions = [
            item
            for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_id"]
            == current.payload["parent_execution_id"]
        ]
        if len(parent_executions) != 1:
            raise CompanyDepartmentLifecycleError(
                "dispatch parent execution is missing",
            )
        if (
            receipt["dispatch_request_id"] != dispatch_request_id
            or receipt["dispatch_revision"]
            != int(current.payload["revision"]) + 1
            or receipt["dispatch_revision_id"]
            != _department_dispatch_revision_id(
                current.payload,
                target_state="dispatched",
                transaction_id=transaction_id,
                command_id=command_id,
            )
            or receipt["organization_node_id"]
            != current.payload["target_node_id"]
        ):
            raise CompanyDepartmentLifecycleError(
                "provider receipt differs from the in-flight dispatch",
            )
        known_carrier = _known_carrier_from_provider_receipt(receipt)
        carrier, carrier_provenance, thread_id, effort = (
            _department_known_carrier(
                self._binding(),
                lead_node_id=str(lead_item.payload["node_id"]),
                known_carrier=known_carrier,
                recorded_at=recorded_at,
            )
        )
        existing_carriers = {
            str(item.payload["carrier_id"]): item
            for item in self.objects(contract_type=CARRIER_BINDING_V1)
        }
        prior_fence: dict[str, Any] | None = None
        carrier_event_type = "department.carrier.bound"
        if carrier_item is not None and carrier_item.payload["state"] == "parked":
            if (
                carrier["carrier_id"] != carrier_item.payload["carrier_id"]
                or carrier["provider"] != carrier_item.payload["provider"]
                or carrier["model"] != carrier_item.payload["model"]
            ):
                raise CompanyDepartmentLifecycleError(
                    "parked carrier resume identity differs",
                )
            carrier = validate_carrier_binding({
                **carrier,
                "bound_at": carrier_item.payload["bound_at"],
            })
            carrier_event_type = "department.carrier.resumed"
        else:
            if carrier["carrier_id"] in existing_carriers:
                raise CompanyDepartmentLifecycleError(
                    "replacement department carrier ID is not fresh",
                )
            if carrier_item is not None:
                prior_fence = validate_carrier_binding({
                    **_plain(carrier_item.payload),
                    "state": "fenced",
                    "last_observed_at": recorded_at,
                    "observation": {
                        "state": "known",
                        "reason": "observed",
                    },
                })
        resolved_event_ids = sorted(
            shadow.source_event_id
            for shadow in self._state.query_snapshot().uncertain_dispatches
            if (
                shadow.dispatch_request_id == dispatch_request_id
                and shadow.reservation_id
                == current.payload["reservation_id"]
            )
        )
        execution_id = _department_dispatch_execution_id(
            current.payload,
            transaction_id=transaction_id,
            carrier_id=str(carrier["carrier_id"]),
        )
        if receipt["execution_id"] != execution_id:
            raise CompanyDepartmentLifecycleError(
                "provider receipt execution identity is not deterministic",
            )
        evidence = _provider_lifecycle_evidence(receipt)
        execution = _department_lead_execution(
            self._binding(),
            dispatch=current.payload,
            parent=parent_executions[0].payload,
            lead=lead_item.payload,
            carrier=carrier,
            thread_id=thread_id,
            effort=effort,
            execution_id=execution_id,
            receipt_id=str(receipt["receipt_id"]),
            evidence_ids=[str(evidence["evidence_id"])],
            provenance=carrier_provenance,
            recorded_at=recorded_at,
        )
        dispatched = _next_department_dispatch_payload(
            current,
            target_state="dispatched",
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            effect_evidence=[receipt["raw_artifact"]],
            reconcile_ref=None,
            provenance=carrier_provenance,
            observation={"state": "known", "reason": "observed"},
            provider_dispatch_id=str(receipt["provider_dispatch_id"]),
            execution_id=execution_id,
            resolves_event_ids=resolved_event_ids,
        )
        digest = company_contract_sha256({
            "dispatch_request_id": dispatch_request_id,
            "transaction_id": transaction_id,
            "command_id": command_id,
        })
        drafts: list[CompanyEventDraft] = [
            *_provider_lifecycle_drafts(receipt, evidence=evidence),
        ]
        if prior_fence is not None:
            drafts.append(CompanyEventDraft(
                event_id=f"department-carrier-fence-{digest}",
                event_type="department.carrier.fenced",
                recorded_at=recorded_at,
                payload=prior_fence,
            ))
        drafts.extend((
            CompanyEventDraft(
                event_id=f"department-carrier-bind-{digest}",
                event_type=carrier_event_type,
                recorded_at=recorded_at,
                payload=carrier,
                provenance=carrier_provenance,
            ),
            CompanyEventDraft(
                event_id=f"department-execution-{digest}",
                event_type="execution.department_lead.created",
                recorded_at=recorded_at,
                payload=execution,
                provenance=carrier_provenance,
            ),
            CompanyEventDraft(
                event_id=_department_dispatch_event_id(
                    dispatched,
                    transaction_id=transaction_id,
                ),
                event_type="dispatch.request.dispatched",
                recorded_at=recorded_at,
                payload=dispatched,
                provenance=carrier_provenance,
            ),
        ))
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=drafts,
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _department_dispatch_result(
            committed.record,
            dispatched,
            idempotent_replay=committed.idempotent_replay,
        )

    def _current_department_dispatch(
        self,
        dispatch_request_id: str,
    ) -> ProjectedObject:
        matches = [
            item
            for item in self.objects(contract_type=DISPATCH_REQUEST_V1)
            if item.payload["dispatch_request_id"] == dispatch_request_id
        ]
        if len(matches) != 1 or matches[0].payload["department_id"] is None:
            raise CompanyDepartmentLifecycleError(
                "department dispatch request is missing or ambiguous",
            )
        return matches[0]

    def _verify_available_blob_refs(
        self,
        references: Sequence[Mapping[str, Any]],
        *,
        label: str,
    ) -> None:
        for reference in references:
            try:
                if reference.get("availability") != "available":
                    raise CompanyDepartmentLifecycleError(
                        f"{label} is not available",
                    )
                metadata = self._state.blobs.metadata(
                    str(reference["sha256"]),
                )
                if metadata.size_bytes != int(reference["size_bytes"]):
                    raise CompanyDepartmentLifecycleError(
                        f"{label} size differs from stored bytes",
                    )
            except CompanyDepartmentLifecycleError:
                raise
            except (
                BlobStoreError,
                OSError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise CompanyDepartmentLifecycleError(
                    f"{label} bytes cannot be verified",
                ) from exc

    def _department_execution_is_park_ready(
        self,
        execution: Mapping[str, Any],
    ) -> bool:
        """Require independent runtime-stop and engineering-idle evidence."""

        if (
            execution["runtime_status"] != "stopped"
            or execution["engineering_status"] != "idle"
            or execution["wait_reason"] != "park_ready"
            or execution["provenance"] != "agent_reported"
            or not execution["evidence_ids"]
            or execution["receipt_id"] is None
        ):
            return False
        receipts = [
            validate_provider_lifecycle_receipt(_plain(item.payload))
            for item in self.objects(
                contract_type=PROVIDER_LIFECYCLE_RECEIPT_V1,
            )
            if (
                item.payload["receipt_id"] == execution["receipt_id"]
                and item.payload["execution_id"]
                == execution["execution_id"]
                and item.payload["event_kind"] == "execution_stopped"
            )
        ]
        if len(receipts) != 1:
            return False
        provider_evidence = _provider_lifecycle_evidence(receipts[0])
        if provider_evidence["evidence_id"] not in execution["evidence_ids"]:
            return False
        dispositions = [
            validate_evidence_record(_plain(item.payload))
            for item in self.objects(contract_type=EVIDENCE_RECORD_V1)
            if (
                item.payload["evidence_id"] in execution["evidence_ids"]
                and item.payload["execution_id"]
                == execution["execution_id"]
                and item.payload["evidence_class"]
                == "engineering_inference"
                and item.payload["status"] == "observed"
                and item.payload["artifact"]["media_type"]
                == ENGINEERING_DISPOSITION_SOURCE_MEDIA_TYPE
                and item.payload["provenance"] == "agent_reported"
            )
        ]
        if (
            len(dispositions) != 1
            or dispositions[0]["evidence_id"]
            != execution["evidence_ids"][-1]
            or dispositions[0]["recorded_at"] != execution["updated_at"]
        ):
            return False
        disposition_receipts = [
            validate_engineering_disposition_receipt(
                _plain(item.payload),
            )
            for item in self.objects(
                contract_type=ENGINEERING_DISPOSITION_RECEIPT_V1,
            )
            if (
                item.payload["receipt_id"]
                == dispositions[0]["claim_id"]
                and item.payload["execution_id"]
                == execution["execution_id"]
                and item.payload["to_status"] == "idle"
            )
        ]
        if (
            len(disposition_receipts) != 1
            or _engineering_disposition_evidence(
                disposition_receipts[0],
            )
            != dispositions[0]
        ):
            return False
        try:
            self._verify_available_blob_refs(
                [
                    receipts[0]["raw_artifact"],
                    disposition_receipts[0]["raw_artifact"],
                ],
                label="department park evidence",
            )
        except CompanyDepartmentLifecycleError:
            return False
        return True

    def _provider_lifecycle_receipt(
        self,
        value: Mapping[str, Any],
        *,
        event_kind: str,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        try:
            receipt = validate_provider_lifecycle_receipt(value)
        except ValueError as exc:
            raise CompanyDepartmentLifecycleError(
                "provider lifecycle receipt is invalid",
            ) from exc
        if (
            {
                "company_id": receipt["company_id"],
                "company_incarnation": receipt["company_incarnation"],
                "lock_domain_generation": receipt["lock_domain_generation"],
            }
            != self._binding()
            or receipt["event_kind"] != event_kind
            or receipt["transaction_id"] != transaction_id
            or receipt["command_id"] != command_id
            or receipt["observed_at"] != recorded_at
        ):
            raise CompanyDepartmentLifecycleError(
                "provider lifecycle receipt differs from the outer command",
            )
        self._verify_available_blob_refs(
            [receipt["raw_artifact"]],
            label="provider lifecycle raw artifact",
        )
        try:
            raw_bytes = self._state.blobs.read(
                str(receipt["raw_artifact"]["sha256"]),
            )
            decoded = json.loads(raw_bytes.decode("utf-8"))
            source = validate_provider_lifecycle_source(decoded)
            if canonical_company_json_bytes(source) != raw_bytes:
                raise CompanyDepartmentLifecycleError(
                    "provider lifecycle source is not canonical JSON",
                )
        except CompanyDepartmentLifecycleError:
            raise
        except (
            BlobStoreError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise CompanyDepartmentLifecycleError(
                "provider lifecycle source bytes are invalid",
            ) from exc
        shared_fields = (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "source_event_id",
            "event_kind",
            "dispatch_request_id",
            "provider_dispatch_id",
            "execution_id",
            "carrier_id",
            "organization_node_id",
            "provider",
            "model",
            "effort",
            "session_id",
            "thread_id",
            "reconcile_ref",
            "observed_at",
            "provenance",
            "observation",
        )
        if any(receipt[field] != source[field] for field in shared_fields):
            raise CompanyDepartmentLifecycleError(
                "provider lifecycle source differs from its typed receipt",
            )
        return receipt

    def _engineering_disposition_receipt(
        self,
        value: Mapping[str, Any],
        *,
        source_bytes: bytes,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        """Cross-bind one caller-supplied agent report to its typed receipt."""

        if (
            not isinstance(source_bytes, bytes)
            or not source_bytes
            or len(source_bytes) > 64 * 1024
        ):
            raise CompanyDepartmentLifecycleError(
                "engineering disposition source bytes are invalid",
            )
        try:
            receipt = validate_engineering_disposition_receipt(value)
            source = validate_engineering_disposition_source(
                json.loads(source_bytes.decode("utf-8")),
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise CompanyDepartmentLifecycleError(
                "engineering disposition source or receipt is invalid",
            ) from exc
        shared_fields = (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "source_event_id",
            "receipt_id",
            "execution_id",
            "expected_execution_payload_sha256",
            "reporter_execution_id",
            "reporter_carrier_id",
            "provider",
            "session_id",
            "thread_id",
            "from_status",
            "to_status",
            "reason_code",
            "result_packet_id",
            "observed_at",
            "provenance",
            "observation",
        )
        source_sha256 = hashlib.sha256(source_bytes).hexdigest()
        if (
            canonical_company_json_bytes(source) != source_bytes
            or {
                key: receipt[key]
                for key in (
                    "company_id",
                    "company_incarnation",
                    "lock_domain_generation",
                )
            }
            != self._binding()
            or receipt["transaction_id"] != transaction_id
            or receipt["command_id"] != command_id
            or receipt["observed_at"] != recorded_at
            or receipt["raw_artifact"]["sha256"] != source_sha256
            or receipt["raw_artifact"]["size_bytes"] != len(source_bytes)
            or any(receipt[field] != source[field] for field in shared_fields)
        ):
            raise CompanyDepartmentLifecycleError(
                "engineering disposition source differs from its receipt",
            )
        return receipt

    def _external_job_effect_receipt(
        self,
        value: Mapping[str, Any],
        *,
        source_bytes: bytes,
    ) -> dict[str, Any]:
        """Validate canonical raw bytes and their typed effect receipt."""

        if (
            not isinstance(source_bytes, bytes)
            or not source_bytes
            or len(source_bytes) > _MAX_EXTERNAL_JOB_EFFECT_SOURCE_BYTES
        ):
            raise CompanyExternalJobError(
                "external job effect source bytes are invalid",
            )
        try:
            receipt = validate_external_job_effect_receipt(value)
            source = validate_external_job_effect_source(
                json.loads(source_bytes.decode("utf-8")),
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise CompanyExternalJobError(
                "external job effect source or receipt is invalid",
            ) from exc
        shared_fields = (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
            "source_event_id",
            "receipt_id",
            "job_id",
            "mutation_intent_id",
            "command_id",
            "transaction_id",
            "transition_command_id",
            "previous_job_state",
            "observed_job_state",
            "external_handle_sha256",
            "process_fingerprint_sha256",
            "reconciliation_id",
            "resolves_reconciliation_id",
            "observed_at",
            "provenance",
            "observation",
        )
        source_sha256 = hashlib.sha256(source_bytes).hexdigest()
        if (
            canonical_company_json_bytes(source) != source_bytes
            or receipt["source_sha256"] != source_sha256
            or receipt["raw_artifact"]["sha256"] != source_sha256
            or receipt["raw_artifact"]["size_bytes"] != len(source_bytes)
            or any(receipt[field] != source[field] for field in shared_fields)
        ):
            raise CompanyExternalJobError(
                "external job effect source differs from its typed receipt",
            )
        return receipt

    def _bind_external_job_effect_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        job: Mapping[str, Any],
        state: str,
        external_handle: Mapping[str, Any] | None,
        transaction_id: str,
        transition_command_id: str,
        recorded_at: str,
    ) -> None:
        """Cross-bind one typed effect receipt to the durable job transition."""

        normalized_handle = (
            None
            if external_handle is None
            else _plain(external_handle)
        )
        expected_handle_sha256 = (
            None
            if normalized_handle is None
            else company_contract_sha256(normalized_handle)
        )
        prior_state = str(job["state"])
        prior_reconcile_ref = job["reconcile_ref"]
        if (
            {
                "company_id": receipt["company_id"],
                "company_incarnation": receipt["company_incarnation"],
                "lock_domain_generation": receipt["lock_domain_generation"],
            }
            != self._binding()
            or receipt["job_id"] != job["job_id"]
            or receipt["mutation_intent_id"]
            != job["mutation_intent_id"]
            or receipt["command_id"] != job["command_id"]
            or receipt["transaction_id"] != transaction_id
            or receipt["transition_command_id"] != transition_command_id
            or receipt["previous_job_state"] != prior_state
            or receipt["observed_job_state"] != state
            or receipt["external_handle_sha256"]
            != expected_handle_sha256
            or receipt["observed_at"] != recorded_at
            or (
                state in {"effect_unknown", "reconcile_required"}
                and prior_state in {"effect_unknown", "reconcile_required"}
                and receipt["reconciliation_id"] != prior_reconcile_ref
            )
            or (
                state in {"completed", "failed_known"}
                and prior_state in {"effect_unknown", "reconcile_required"}
                and receipt["resolves_reconciliation_id"]
                != prior_reconcile_ref
            )
            or (
                state in {"completed", "failed_known"}
                and prior_state not in {"effect_unknown", "reconcile_required"}
                and receipt["resolves_reconciliation_id"] is not None
            )
            or receipt["raw_artifact"]["sha256"]
            == job["command_blob"]["sha256"]
        ):
            raise CompanyExternalJobError(
                "external job effect receipt differs from its durable job",
            )

    def stop_department_execution(
        self,
        execution_id: str,
        provider_receipt: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExecutionRuntimeStatusResult:
        """Record a provider-observed runtime stop without inferring completion."""

        receipt = self._provider_lifecycle_receipt(
            provider_receipt,
            event_kind="execution_stopped",
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
        )
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _department_execution_stop_replay(
                durable,
                execution_id=execution_id,
                command_id=command_id,
                provider_receipt=receipt,
                recorded_at=recorded_at,
            )
        matches = [
            item
            for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_id"] == execution_id
        ]
        if len(matches) != 1:
            raise CompanyDepartmentLifecycleError(
                "department execution is missing or ambiguous",
            )
        current = matches[0]
        dispatch_id = current.payload["dispatch_id"]
        department_id = current.payload["department_id"]
        if (
            current.payload["execution_kind"] != "agent"
            or not isinstance(dispatch_id, str)
            or not isinstance(department_id, str)
            or current.payload["runtime_status"]
            not in {"running", "telemetry_silent", "unknown"}
            or current.payload["engineering_status"]
            in {"completed", "cancelled"}
        ):
            raise CompanyDepartmentLifecycleError(
                "execution is not a stoppable department lead",
            )
        if _parsed_time(recorded_at) < _parsed_time(
            str(current.payload["updated_at"]),
        ):
            raise CompanyDepartmentLifecycleError(
                "provider stop observation predates department execution",
            )
        dispatch = self._current_department_dispatch(dispatch_id)
        if (
            dispatch.payload["state"] != "dispatched"
            or dispatch.payload["execution_id"] != execution_id
            or dispatch.payload["department_id"] != department_id
        ):
            raise CompanyDepartmentLifecycleError(
                "department execution dispatch binding differs",
            )
        carriers = [
            item
            for item in self.objects(contract_type=CARRIER_BINDING_V1)
            if item.payload["carrier_id"] == current.payload["carrier_id"]
        ]
        if len(carriers) != 1:
            raise CompanyDepartmentLifecycleError(
                "department execution carrier is missing or ambiguous",
            )
        carrier = carriers[0].payload
        if (
            receipt["execution_id"] != execution_id
            or receipt["dispatch_request_id"] != dispatch_id
            or receipt["dispatch_revision"] != dispatch.payload["revision"]
            or receipt["dispatch_revision_id"]
            != dispatch.payload["dispatch_revision_id"]
            or receipt["provider_dispatch_id"]
            != dispatch.payload["provider_dispatch_id"]
            or receipt["organization_node_id"]
            != current.payload["organization_node_id"]
            or receipt["carrier_id"] != current.payload["carrier_id"]
            or receipt["provider"] != current.payload["provider"]
            or receipt["model"] != current.payload["model"]
            or receipt["effort"] != current.payload["effort"]
            or receipt["thread_id"] != current.payload["thread_id"]
            or receipt["session_id"] != carrier["session_id"]
        ):
            raise CompanyDepartmentLifecycleError(
                "provider stop receipt differs from durable runtime identity",
            )
        evidence = _provider_lifecycle_evidence(receipt)
        candidate = {
            **_plain(current.payload),
            "runtime_status": "stopped",
            "updated_at": recorded_at,
            "last_event_at": recorded_at,
            "heartbeat_at": None,
            "current_tool": None,
            "receipt_id": receipt["receipt_id"],
            "evidence_ids": [
                *current.payload["evidence_ids"],
                evidence["evidence_id"],
            ],
            "provenance": receipt["provenance"],
            "observation": receipt["observation"],
        }
        try:
            stopped = validate_execution_node(candidate)
        except ValueError as exc:
            raise CompanyDepartmentLifecycleError(
                "department execution stop record is invalid",
            ) from exc
        event_id = _department_execution_stop_event_id(
            execution_id,
            transaction_id=transaction_id,
            command_id=command_id,
        )
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                *_provider_lifecycle_drafts(receipt, evidence=evidence),
                CompanyEventDraft(
                    event_id=event_id,
                    event_type="execution.department_lead.stopped",
                    recorded_at=recorded_at,
                    payload=stopped,
                    provenance=str(receipt["provenance"]),
                ),
            ],
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _department_execution_status_result(
            committed.record,
            stopped,
            idempotent_replay=committed.idempotent_replay,
        )

    def record_department_execution_idle(
        self,
        execution_id: str,
        disposition_source_bytes: bytes,
        disposition_receipt: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
        result_bytes: bytes | None = None,
        result_media_type: str | None = None,
    ) -> ExecutionRuntimeStatusResult:
        """Record an idle disposition and, for registered work, its exact result."""

        receipt = self._engineering_disposition_receipt(
            disposition_receipt,
            source_bytes=disposition_source_bytes,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
        )
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _department_execution_idle_replay(
                durable,
                execution_id=execution_id,
                command_id=command_id,
                receipt=receipt,
                source_bytes=disposition_source_bytes,
                state_owner=self._state,
                recorded_at=recorded_at,
                result_bytes=result_bytes,
                result_media_type=result_media_type,
            )
        matches = [
            item
            for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_id"] == execution_id
        ]
        if len(matches) != 1:
            raise CompanyDepartmentLifecycleError(
                "department execution is missing or ambiguous",
            )
        current = matches[0]
        if (
            current.payload["execution_kind"] != "agent"
            or current.payload["dispatch_id"] is None
            or current.payload["department_id"] is None
            or current.payload["runtime_status"] != "stopped"
            or current.payload["engineering_status"]
            in {"completed", "cancelled", "idle"}
            or current.payload["receipt_id"] is None
        ):
            raise CompanyDepartmentLifecycleError(
                "department execution is not awaiting an idle disposition",
            )
        if _parsed_time(recorded_at) < _parsed_time(
            str(current.payload["updated_at"]),
        ):
            raise CompanyDepartmentLifecycleError(
                "engineering disposition predates the runtime stop",
            )
        carriers = [
            item
            for item in self.objects(contract_type=CARRIER_BINDING_V1)
            if item.payload["carrier_id"] == current.payload["carrier_id"]
        ]
        if len(carriers) != 1:
            raise CompanyDepartmentLifecycleError(
                "department execution carrier is missing or ambiguous",
            )
        carrier = carriers[0].payload
        if (
            receipt["execution_id"] != execution_id
            or receipt["expected_execution_payload_sha256"]
            != company_contract_sha256(_plain(current.payload))
            or receipt["reporter_execution_id"] != execution_id
            or receipt["reporter_carrier_id"]
            != current.payload["carrier_id"]
            or receipt["provider"] != current.payload["provider"]
            or receipt["session_id"] != carrier["session_id"]
            or receipt["thread_id"] != current.payload["thread_id"]
            or receipt["from_status"]
            != current.payload["engineering_status"]
            or receipt["to_status"] != "idle"
            or receipt["result_packet_id"] != current.payload["packet_id"]
            or receipt["provenance"] != "agent_reported"
            or receipt["observation"]
            != {"state": "known", "reason": "observed"}
        ):
            raise CompanyDepartmentLifecycleError(
                "engineering disposition differs from durable execution",
            )
        bindings = [
            item
            for item in self.objects(contract_type=WORK_DISPATCH_BINDING_V1)
            if item.payload["dispatch_request_id"]
            == current.payload["dispatch_id"]
        ]
        if len(bindings) > 1:
            raise CompanyDepartmentLifecycleError(
                "department execution work binding is ambiguous",
            )
        work_binding = None if not bindings else _plain(bindings[0].payload)
        has_any_result_input = (
            result_bytes is not None or result_media_type is not None
        )
        if work_binding is None:
            if has_any_result_input:
                raise CompanyDepartmentLifecycleError(
                    "legacy department execution cannot publish a work result",
                )
        else:
            if (
                type(result_bytes) is not bytes
                or not result_bytes
                or len(result_bytes) > _MAX_WORK_RESULT_BYTES
                or not isinstance(result_media_type, str)
                or not result_media_type
                or "\x00" in result_media_type
            ):
                raise CompanyDepartmentLifecycleError(
                    "registered work result bytes or media type are invalid",
                )
            try:
                if len(result_media_type.encode("utf-8")) > 128:
                    raise CompanyDepartmentLifecycleError(
                        "registered work result media type is too large",
                    )
            except UnicodeEncodeError as exc:
                raise CompanyDepartmentLifecycleError(
                    "registered work result media type is invalid Unicode",
                ) from exc
            tasks = [
                item
                for item in self.objects(contract_type=TASK_REVISION_V1)
                if item.payload["task_revision_id"]
                == work_binding["task_revision_id"]
            ]
            packets = [
                item
                for item in self.objects(contract_type=WORK_PACKET_V1)
                if item.payload["packet_id"] == work_binding["packet_id"]
            ]
            if (
                len(tasks) != 1
                or len(packets) != 1
                or current.payload["task_id"] != work_binding["task_id"]
                or current.payload["packet_id"] != work_binding["packet_id"]
                or tasks[0].payload["task_id"] != work_binding["task_id"]
                or tasks[0].payload["task_sha256"]
                != work_binding["task_sha256"]
                or packets[0].payload["task_revision_id"]
                != work_binding["task_revision_id"]
                or packets[0].payload["packet_sha256"]
                != work_binding["packet_sha256"]
            ):
                raise CompanyDepartmentLifecycleError(
                    "department execution differs from its registered work binding",
                )
        metadata = self._state.blobs.put(disposition_source_bytes)
        if (
            metadata.sha256 != receipt["raw_artifact"]["sha256"]
            or metadata.size_bytes != receipt["raw_artifact"]["size_bytes"]
        ):
            raise CompanyDepartmentLifecycleError(
                "engineering disposition source publication differs",
            )
        work_result = None
        if work_binding is not None:
            assert result_bytes is not None
            assert result_media_type is not None
            result_metadata = self._state.blobs.put(result_bytes)
            if self._state.blobs.read(result_metadata.sha256) != result_bytes:
                raise CompanyDepartmentLifecycleError(
                    "registered work result CAS readback differs",
                )
            result_ref = _blob_ref(
                result_metadata.sha256,
                result_metadata.size_bytes,
                result_media_type,
            )
            result_unsigned = {
                "contract_type": WORK_RESULT_RECEIPT_V1,
                "schema_version": 1,
                **self._binding(),
                "result_receipt_id": _work_definition_id(
                    self._binding(),
                    "result-receipt",
                    transaction_id,
                ),
                "task_id": work_binding["task_id"],
                "task_revision_id": work_binding["task_revision_id"],
                "task_sha256": work_binding["task_sha256"],
                "packet_id": work_binding["packet_id"],
                "packet_sha256": work_binding["packet_sha256"],
                "producer_execution_id": execution_id,
                "expected_execution_payload_sha256":
                    company_contract_sha256(_plain(current.payload)),
                "engineering_disposition_receipt_id": receipt["receipt_id"],
                "result_ref": result_ref,
                "recorded_at": recorded_at,
                "provenance": "AOI_verified",
                "observation": {"state": "known", "reason": "observed"},
            }
            try:
                work_result = validate_work_result_receipt({
                    **result_unsigned,
                    "receipt_sha256": company_contract_sha256(result_unsigned),
                })
            except ValueError as exc:
                raise CompanyDepartmentLifecycleError(
                    "registered work result receipt is invalid",
                ) from exc
        evidence = _engineering_disposition_evidence(receipt)
        candidate = {
            **_plain(current.payload),
            "engineering_status": "idle",
            "updated_at": recorded_at,
            "last_event_at": recorded_at,
            "wait_reason": "park_ready",
            "current_tool": None,
            "evidence_ids": [
                *current.payload["evidence_ids"],
                evidence["evidence_id"],
            ],
            "provenance": "agent_reported",
            "observation": {"state": "known", "reason": "observed"},
        }
        try:
            idle = validate_execution_node(candidate)
        except ValueError as exc:
            raise CompanyDepartmentLifecycleError(
                "department engineering disposition is invalid",
            ) from exc
        event_id = _department_execution_idle_event_id(
            execution_id,
            transaction_id=transaction_id,
            command_id=command_id,
        )
        result_drafts = (
            []
            if work_result is None
            else [
                CompanyEventDraft(
                    event_id=_work_definition_id(
                        self._binding(),
                        "result-event",
                        transaction_id,
                    ),
                    event_type="work.result.recorded",
                    recorded_at=recorded_at,
                    payload=work_result,
                    provenance="AOI_verified",
                ),
            ]
        )
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                _engineering_disposition_receipt_draft(receipt),
                CompanyEventDraft(
                    event_id=str(evidence["evidence_id"]),
                    event_type="evidence.engineering_disposition.observed",
                    recorded_at=recorded_at,
                    payload=evidence,
                    provenance="agent_reported",
                ),
                CompanyEventDraft(
                    event_id=event_id,
                    event_type="execution.department_lead.idle",
                    recorded_at=recorded_at,
                    payload=idle,
                    provenance="agent_reported",
                ),
                *result_drafts,
            ],
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _department_execution_status_result(
            committed.record,
            idle,
            idempotent_replay=committed.idempotent_replay,
        )

    def record_provider_turn_engineering_idle(
        self,
        execution_id: str,
        result_receipt_id: str,
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExecutionRuntimeStatusResult:
        """Durably hand off one stopped, completed provider turn as engineering-idle.

        This is deliberately not a department self-report or a WorkResult.  The
        only authority for the transition is an already durable, canonical
        ProviderTurnResult and the earlier B49 process-exit stop.
        """

        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _provider_turn_idle_replay(
                durable,
                execution_id=execution_id,
                result_receipt_id=result_receipt_id,
                command_id=command_id,
                recorded_at=recorded_at,
                state_owner=self._state,
            )
        matches = [
            item for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_id"] == execution_id
        ]
        if len(matches) != 1:
            raise CompanyDepartmentLifecycleError(
                "provider turn execution is missing or ambiguous",
            )
        current = matches[0]
        if (
            current.payload["execution_kind"] != "turn"
            or current.payload["runtime_status"] != "stopped"
            or current.payload["engineering_status"] in {"completed", "cancelled", "idle"}
            or current.payload["registration_id"] is None
            or current.payload["parent_execution_id"] is None
            or current.payload["carrier_id"] is None
        ):
            raise CompanyDepartmentLifecycleError(
                "provider turn is not awaiting an engineering idle disposition",
            )
        result_matches = [
            item
            for item in self.objects(contract_type=PROVIDER_TURN_RESULT_RECEIPT_V1)
            if item.payload["result_receipt_id"] == result_receipt_id
        ]
        if len(result_matches) != 1:
            raise CompanyDepartmentLifecycleError(
                "provider turn result receipt is missing or ambiguous",
            )
        try:
            result_receipt = validate_provider_turn_result_receipt(
                _plain(result_matches[0].payload),
            )
            result_raw = self._state.blobs.read(
                str(result_receipt["result_ref"]["sha256"]),
            )
            result_document = validate_provider_turn_result(
                json.loads(result_raw.decode("utf-8")),
            )
        except (
            BlobStoreError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise CompanyDepartmentLifecycleError(
                "provider turn result CAS is unavailable or invalid",
            ) from exc
        if canonical_provider_turn_result_bytes(result_document) != result_raw:
            raise CompanyDepartmentLifecycleError(
                "provider turn result CAS is not canonical",
            )
        launches = [
            item for item in self.objects(contract_type=PROVIDER_LAUNCH_BINDING_V1)
            if item.payload["launch_binding_id"] == current.payload["registration_id"]
        ]
        parents = [
            item for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_id"] == current.payload["parent_execution_id"]
        ]
        if len(launches) != 1 or len(parents) != 1:
            raise CompanyDepartmentLifecycleError(
                "provider turn launch or parent agent is missing or ambiguous",
            )
        launch, parent = launches[0].payload, parents[0].payload
        if (
            parent["execution_kind"] != "agent"
            or parent["dispatch_id"] != launch["dispatch_request_id"]
            or parent["thread_id"] != current.payload["thread_id"]
            or parent["carrier_id"] != current.payload["carrier_id"]
            or any(
                node[field] != launch[field]
                for node in (parent, current.payload)
                for field in ("provider", "model", "effort")
            )
            or tuple(result_receipt[field] for field in (
                "launch_binding_id", "launch_binding_sha256", "agent_execution_id",
                "turn_execution_id", "thread_id", "turn_id",
            )) != (
                launch["launch_binding_id"], launch["binding_sha256"],
                parent["execution_id"], current.payload["execution_id"],
                current.payload["thread_id"], current.payload["turn_id"],
            )
            or result_receipt["terminal_status"] != "completed"
            or tuple(result_document[field] for field in (
                "launch_binding_id", "launch_binding_sha256", "operation_id",
                "agent_execution_id", "turn_execution_id", "thread_id", "turn_id",
                "terminal_status",
            )) != tuple(result_receipt[field] for field in (
                "launch_binding_id", "launch_binding_sha256", "operation_id",
                "agent_execution_id", "turn_execution_id", "thread_id", "turn_id",
                "terminal_status",
            ))
            or result_document["availability"] != "available"
            or result_document["items_view"] != "summary"
            or result_document["reason"] != "observed"
            or not result_document["agent_message_items"]
        ):
            raise CompanyDepartmentLifecycleError(
                "provider turn result differs from its exact stopped execution",
            )
        if (
            hashlib.sha256(result_raw).hexdigest()
            != result_receipt["result_ref"]["sha256"]
            or len(result_raw) != result_receipt["result_ref"]["size_bytes"]
        ):
            raise CompanyDepartmentLifecycleError(
                "provider turn result CAS differs from its receipt",
            )
        exits = [
            item.payload
            for item in self.objects(contract_type=PROVIDER_WORKER_IO_RECEIPT_V1)
            if (
                item.payload["launch_binding_id"] == launch["launch_binding_id"]
                and item.payload["phase"] == "process_exit_observed"
                and item.payload["execution_id"] == execution_id
                and item.payload["thread_id"] == current.payload["thread_id"]
                and item.payload["turn_id"] == current.payload["turn_id"]
            )
        ]
        if len(exits) != 1:
            raise CompanyDepartmentLifecycleError(
                "provider turn lacks one exact durable process exit",
            )
        terminals = [
            item.payload
            for item in self.objects(contract_type=PROVIDER_WORKER_IO_RECEIPT_V1)
            if item.payload["receipt_id"] == result_receipt["terminal_io_receipt_id"]
        ]
        operations = [
            item.payload
            for item in self.objects(contract_type=PROVIDER_WORKER_OPERATION_V1)
            if item.payload["operation_id"] == result_receipt["operation_id"]
        ]
        if len(terminals) != 1 or len(operations) != 1:
            raise CompanyDepartmentLifecycleError(
                "provider turn terminal or result operation is missing or ambiguous",
            )
        try:
            validate_provider_turn_result_lifecycle(
                result_receipt, result_document, terminals[0], exits[0],
                operations[0], launch, parent, current.payload, recorded_at,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CompanyDepartmentLifecycleError(
                "provider turn result differs from its exact stopped execution",
            ) from exc
        if any(
            _parsed_time(recorded_at) < _parsed_time(str(value))
            for value in (
                exits[0]["observed_at"], result_receipt["recorded_at"],
                current.payload["updated_at"],
            )
        ):
            raise CompanyDepartmentLifecycleError(
                "provider turn idle disposition predates durable result or stop",
            )
        evidence = _provider_turn_idle_evidence(
            result_receipt,
            execution_id=execution_id,
            recorded_at=recorded_at,
        )
        candidate = {
            **_plain(current.payload),
            "engineering_status": "idle",
            "updated_at": recorded_at,
            "last_event_at": recorded_at,
            "wait_reason": "park_ready",
            "current_tool": None,
            "evidence_ids": [
                *current.payload["evidence_ids"], evidence["evidence_id"],
            ],
            "provenance": "AOI_verified",
            "observation": {"state": "known", "reason": "observed"},
        }
        try:
            idle = validate_execution_node(candidate)
        except ValueError as exc:
            raise CompanyDepartmentLifecycleError(
                "provider turn engineering idle disposition is invalid",
            ) from exc
        event_id = _provider_turn_idle_event_id(
            execution_id,
            result_receipt_id=result_receipt_id,
            transaction_id=transaction_id,
            command_id=command_id,
        )
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                CompanyEventDraft(
                    event_id=str(evidence["evidence_id"]),
                    event_type="evidence.provider_turn.idle.observed",
                    recorded_at=recorded_at,
                    payload=evidence,
                    provenance="AOI_verified",
                ),
                CompanyEventDraft(
                    event_id=event_id,
                    event_type="execution.provider_turn.idle",
                    recorded_at=recorded_at,
                    payload=idle,
                    provenance="AOI_verified",
                ),
            ],
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _department_execution_status_result(
            committed.record,
            idle,
            idempotent_replay=committed.idempotent_replay,
        )

    def record_execution_runtime_observation(
        self,
        execution_id: str,
        receipt_value: Mapping[str, Any],
        *,
        source_bytes: bytes,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExecutionRuntimeStatusResult:
        """Persist a nonterminal runtime observation without inferring completion."""
        try:
            receipt = validate_execution_runtime_observation_receipt(receipt_value)
            source = validate_execution_runtime_observation_source(json.loads(source_bytes.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise CompanyExecutionRegistrationError("runtime observation source or receipt is invalid") from exc
        shared = (
            "company_id", "company_incarnation", "lock_domain_generation", "source_event_id", "receipt_id",
            "execution_id", "carrier_id", "transition", "activity_kind", "provider_registry", "host_process",
            "terminal_grace", "collector_health", "observed_at", "provenance", "observation",
        )
        if (canonical_company_json_bytes(source) != source_bytes or any(receipt[field] != source[field] for field in shared) or receipt["transaction_id"] != transaction_id or receipt["command_id"] != command_id or receipt["observed_at"] != recorded_at or receipt["execution_id"] != execution_id or {key: receipt[key] for key in ("company_id", "company_incarnation", "lock_domain_generation")} != self._binding()):
            raise CompanyExecutionRegistrationError("runtime observation differs from its outer command")
        if hashlib.sha256(source_bytes).hexdigest() != receipt["raw_artifact"]["sha256"] or len(source_bytes) != receipt["raw_artifact"]["size_bytes"] or receipt["raw_artifact"]["media_type"] != EXECUTION_RUNTIME_OBSERVATION_SOURCE_MEDIA_TYPE:
            raise CompanyExecutionRegistrationError("runtime observation raw artifact differs")
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _runtime_observation_replay(durable, execution_id=execution_id, receipt=receipt, source_bytes=source_bytes, command_id=command_id, recorded_at=recorded_at)
        prior_receipts = [
            validate_execution_runtime_observation_receipt(_plain(item.payload))
            for item in self.objects(
                contract_type=EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1,
            )
        ]
        if any(
            prior["receipt_id"] == receipt["receipt_id"]
            or prior["source_event_id"] == receipt["source_event_id"]
            for prior in prior_receipts
        ):
            raise CompanyExecutionRegistrationError(
                "runtime observation receipt or source event was already used",
            )
        matching = [item for item in self.objects(contract_type=EXECUTION_NODE_V1) if item.payload["execution_id"] == execution_id]
        if len(matching) != 1:
            raise CompanyExecutionRegistrationError("runtime observation execution is missing or ambiguous")
        current = matching[0].payload
        if current["carrier_id"] != receipt["carrier_id"] or current["engineering_status"] in {"completed", "cancelled"}:
            raise CompanyExecutionRegistrationError("runtime observation execution binding is invalid")
        recovery_heartbeat_at: str | None = None
        if receipt["transition"] == "recovered":
            telemetry_matches = [
                validate_provider_telemetry_receipt(_plain(item.payload))
                for item in self.objects(
                    contract_type=PROVIDER_TELEMETRY_RECEIPT_V1,
                )
                if item.payload["receipt_id"] == receipt["source_event_id"]
            ]
            if len(telemetry_matches) != 1:
                raise CompanyExecutionRegistrationError(
                    "runtime recovery lacks one durable provider receipt",
                )
            telemetry = telemetry_matches[0]
            join = telemetry["dispatch_join"]
            relation = telemetry["provider_native_relation"]
            activity_kind = receipt["activity_kind"]
            activity_matches = (
                activity_kind == "codex.item_started"
                and telemetry["provider"] == "codex"
                and telemetry["normalized_kind"]
                == "item_started_runtime_observed"
            ) or (
                activity_kind == "codex.subagent_activity"
                and telemetry["provider"] == "codex"
                and telemetry["normalized_kind"]
                in {
                    "item_started_runtime_observed",
                    "item_completed_runtime_observed",
                }
                and relation["kind"] == "subagent_activity"
            ) or (
                activity_kind == "claude.subagent_started"
                and telemetry["provider"] == "claude"
                and telemetry["normalized_kind"]
                == "subagent_start_runtime_observed"
            )
            if (
                not activity_matches
                or telemetry["provider"] != current["provider"]
                or join["state"] != "exact"
                or join["execution_id"] != execution_id
                or join["carrier_id"] != current["carrier_id"]
                or _parsed_time(telemetry["received_at"])
                <= _parsed_time(current["updated_at"])
                or _parsed_time(telemetry["received_at"])
                > _parsed_time(receipt["observed_at"])
            ):
                raise CompanyExecutionRegistrationError(
                    "runtime recovery provider receipt binding is invalid",
                )
            recovery_heartbeat_at = str(telemetry["received_at"])
        metadata = self._state.blobs.put(source_bytes)
        if metadata.sha256 != receipt["raw_artifact"]["sha256"] or metadata.size_bytes != receipt["raw_artifact"]["size_bytes"]:
            raise CompanyExecutionRegistrationError("runtime observation source publication differs")
        evidence = _runtime_observation_evidence(receipt)
        transition = receipt["transition"]
        status = {
            "telemetry_silent": "telemetry_silent",
            "recovered": "running",
            "confirmed_lost": "confirmed_lost",
        }[transition]
        candidate = {
            **_plain(current),
            "runtime_status": status,
            "updated_at": recorded_at,
            "last_event_at": recorded_at,
            "evidence_ids": [
                *current["evidence_ids"],
                evidence["evidence_id"],
            ],
            # The typed receipt/event owns the AOI inference.  Preserve the
            # node's provider-grade provenance for silent/recovered runtime;
            # only the explicit confirmed-loss fact is AOI-verified on-node.
            "provenance": (
                receipt["provenance"]
                if transition == "confirmed_lost"
                else current["provenance"]
            ),
            "observation": (
                _plain(receipt["observation"])
                if transition == "confirmed_lost"
                else _plain(current["observation"])
            ),
        }
        if recovery_heartbeat_at is not None:
            candidate["heartbeat_at"] = recovery_heartbeat_at
        try:
            execution = validate_execution_node(candidate)
        except ValueError as exc:
            raise CompanyExecutionRegistrationError("runtime observation execution revision is invalid") from exc
        events: list[CompanyEventDraft] = [
            CompanyEventDraft(event_id=f"runtime-observation-receipt-{receipt['receipt_sha256']}", event_type=f"runtime.observation.{transition}", recorded_at=recorded_at, payload=receipt, provenance=str(receipt["provenance"])),
            CompanyEventDraft(event_id=evidence["evidence_id"], event_type="evidence.runtime_observation.observed", recorded_at=recorded_at, payload=evidence, provenance=str(receipt["provenance"])),
        ]
        if transition == "confirmed_lost":
            alert = _runtime_observation_alert(receipt)
            events.append(CompanyEventDraft(
                event_id=str(alert["alert_id"]),
                event_type="alert.execution.confirmed_lost",
                recorded_at=recorded_at,
                payload=alert,
                provenance="AOI_verified",
            ))
            # Absence evidence is scoped to this execution identity.  A shared
            # provider carrier stays occupied while any sibling execution is
            # still runtime-active.
            siblings = [item for item in self.objects(contract_type=EXECUTION_NODE_V1) if item.payload["carrier_id"] == receipt["carrier_id"] and item.payload["execution_id"] != execution_id and item.payload["runtime_status"] in {"running", "telemetry_silent", "unknown"}]
            if not siblings:
                carriers = [item for item in self.objects(contract_type=CARRIER_BINDING_V1) if item.payload["carrier_id"] == receipt["carrier_id"]]
                if len(carriers) != 1: raise CompanyExecutionRegistrationError("runtime observation carrier is missing or ambiguous")
                lost = validate_carrier_binding({**_plain(carriers[0].payload), "state": "lost", "session_id": None, "session_availability": "unavailable", "last_observed_at": recorded_at, "observation": _plain(receipt["observation"])})
                events.append(CompanyEventDraft(event_id=f"carrier-runtime-lost-{receipt['receipt_sha256']}", event_type="carrier.runtime.confirmed_lost", recorded_at=recorded_at, payload=lost, provenance=str(receipt["provenance"])))
        events.append(CompanyEventDraft(event_id=f"execution-runtime-{transition}-{receipt['receipt_sha256']}", event_type=f"execution.runtime.{transition}", recorded_at=recorded_at, payload=execution, provenance=str(receipt["provenance"])))
        committed = self.commit(build_company_transaction_request(self.heads(), self._supervisor_authority(), transaction_id=transaction_id, command_id=command_id, events=events), recorded_at=recorded_at)
        return _department_execution_status_result(committed.record, execution, idempotent_replay=committed.idempotent_replay)

    def record_fenced_chief_execution_stopped(
        self,
        execution_id: str,
        provider_receipt: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExecutionRuntimeStatusResult:
        """Record a provider-confirmed fenced Chief runtime stop."""

        try:
            receipt = self._provider_lifecycle_receipt(
                provider_receipt,
                event_kind="execution_stopped",
                transaction_id=transaction_id,
                command_id=command_id,
                recorded_at=recorded_at,
            )
        except CompanyDepartmentLifecycleError as exc:
            raise CompanyChiefTakeoverError(
                "fenced Chief provider stop receipt is invalid",
            ) from exc
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _fenced_chief_execution_stop_replay(
                durable,
                execution_id=execution_id,
                command_id=command_id,
                provider_receipt=receipt,
                recorded_at=recorded_at,
            )
        matches = [
            item
            for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_id"] == execution_id
        ]
        if len(matches) != 1:
            raise CompanyChiefTakeoverError(
                "fenced Chief execution is missing or ambiguous",
            )
        current = matches[0]
        if (
            current.payload["execution_kind"] != "carrier"
            or current.payload["role"] != "chief"
            or current.payload["department_id"] is not None
            or current.payload["parent_execution_id"] is not None
            or current.payload["dispatch_id"] is not None
            or current.payload["runtime_status"]
            not in {"running", "telemetry_silent", "unknown"}
            or current.payload["engineering_status"] != "waiting"
            or current.payload["wait_reason"] != "fenced_read_only"
        ):
            raise CompanyChiefTakeoverError(
                "execution is not a stoppable fenced Chief carrier",
            )
        if _parsed_time(recorded_at) < _parsed_time(
            str(current.payload["updated_at"]),
        ):
            raise CompanyChiefTakeoverError(
                "provider stop observation predates the Chief fence",
            )
        carriers = [
            item
            for item in self.objects(contract_type=CARRIER_BINDING_V1)
            if item.payload["carrier_id"] == current.payload["carrier_id"]
        ]
        if len(carriers) != 1 or carriers[0].payload["state"] != "fenced":
            raise CompanyChiefTakeoverError(
                "Chief execution carrier is not durably fenced",
            )
        carrier = carriers[0].payload
        if (
            receipt["dispatch_request_id"] is not None
            or receipt["dispatch_revision_id"] is not None
            or receipt["dispatch_revision"] is not None
            or receipt["provider_dispatch_id"] is not None
            or receipt["execution_id"] != execution_id
            or receipt["organization_node_id"]
            != current.payload["organization_node_id"]
            or receipt["carrier_id"] != current.payload["carrier_id"]
            or receipt["provider"] != current.payload["provider"]
            or receipt["model"] != current.payload["model"]
            or receipt["effort"] != current.payload["effort"]
            or receipt["thread_id"] != current.payload["thread_id"]
            or receipt["session_id"] != carrier["session_id"]
        ):
            raise CompanyChiefTakeoverError(
                "provider stop receipt differs from fenced Chief runtime",
            )
        evidence = _provider_lifecycle_evidence(receipt)
        candidate = {
            **_plain(current.payload),
            "runtime_status": "stopped",
            "updated_at": recorded_at,
            "last_event_at": recorded_at,
            "heartbeat_at": None,
            "current_tool": None,
            "receipt_id": receipt["receipt_id"],
            "evidence_ids": [
                *current.payload["evidence_ids"],
                evidence["evidence_id"],
            ],
            "provenance": receipt["provenance"],
            "observation": receipt["observation"],
        }
        try:
            stopped = validate_execution_node(candidate)
        except ValueError as exc:
            raise CompanyChiefTakeoverError(
                "fenced Chief execution stop record is invalid",
            ) from exc
        event_id = _fenced_chief_execution_stop_event_id(
            execution_id,
            transaction_id=transaction_id,
            command_id=command_id,
        )
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                *_provider_lifecycle_drafts(receipt, evidence=evidence),
                CompanyEventDraft(
                    event_id=event_id,
                    event_type="execution.chief_fenced.stopped",
                    recorded_at=recorded_at,
                    payload=stopped,
                    provenance=str(receipt["provenance"]),
                ),
            ],
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _department_execution_status_result(
            committed.record,
            stopped,
            idempotent_replay=committed.idempotent_replay,
        )

    def record_current_chief_execution_stopped(
        self,
        execution_id: str,
        provider_receipt: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExecutionRuntimeStatusResult:
        """Stop the current carrier, revoke its availability, and preserve term."""

        try:
            receipt = self._provider_lifecycle_receipt(
                provider_receipt,
                event_kind="execution_stopped",
                transaction_id=transaction_id,
                command_id=command_id,
                recorded_at=recorded_at,
            )
        except CompanyDepartmentLifecycleError as exc:
            raise CompanyChiefTakeoverError(
                "current Chief provider stop receipt is invalid",
            ) from exc
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _current_chief_execution_stop_replay(
                durable,
                execution_id=execution_id,
                command_id=command_id,
                provider_receipt=receipt,
                recorded_at=recorded_at,
            )
        term, carrier, _chief_node_id = self._current_chief_context()
        matches = [
            item
            for item in self.objects(contract_type=EXECUTION_NODE_V1)
            if item.payload["execution_id"] == execution_id
        ]
        if len(matches) != 1:
            raise CompanyChiefTakeoverError(
                "current Chief execution is missing or ambiguous",
            )
        current = matches[0]
        if (
            term["carrier_id"] != carrier["carrier_id"]
            or current.payload["execution_kind"] != "carrier"
            or current.payload["role"] != "chief"
            or current.payload["department_id"] is not None
            or current.payload["parent_execution_id"] is not None
            or current.payload["dispatch_id"] is not None
            or current.payload["carrier_id"] != carrier["carrier_id"]
            or carrier["state"] != "active"
            or carrier["session_availability"] != "available"
            or current.payload["runtime_status"]
            not in {"running", "telemetry_silent", "unknown"}
            or current.payload["engineering_status"]
            in {"completed", "cancelled"}
        ):
            raise CompanyChiefTakeoverError(
                "execution is not the available current Chief carrier",
            )
        if _parsed_time(recorded_at) < _parsed_time(
            str(current.payload["updated_at"]),
        ):
            raise CompanyChiefTakeoverError(
                "provider stop observation predates the current Chief",
            )
        if (
            receipt["dispatch_request_id"] is not None
            or receipt["dispatch_revision_id"] is not None
            or receipt["dispatch_revision"] is not None
            or receipt["provider_dispatch_id"] is not None
            or receipt["execution_id"] != execution_id
            or receipt["organization_node_id"]
            != current.payload["organization_node_id"]
            or receipt["carrier_id"] != current.payload["carrier_id"]
            or receipt["provider"] != current.payload["provider"]
            or receipt["model"] != current.payload["model"]
            or receipt["effort"] != current.payload["effort"]
            or receipt["thread_id"] != current.payload["thread_id"]
            or receipt["session_id"] != carrier["session_id"]
        ):
            raise CompanyChiefTakeoverError(
                "provider stop receipt differs from current Chief runtime",
            )
        evidence = _provider_lifecycle_evidence(receipt)
        try:
            lost_carrier = validate_carrier_binding({
                **carrier,
                "session_id": None,
                "session_availability": "unavailable",
                "state": "lost",
                "last_observed_at": recorded_at,
                "observation": _plain(receipt["observation"]),
            })
            stopped = validate_execution_node({
                **_plain(current.payload),
                "runtime_status": "stopped",
                "updated_at": recorded_at,
                "last_event_at": recorded_at,
                "heartbeat_at": None,
                "wait_reason": "carrier_stopped",
                "current_tool": None,
                "receipt_id": receipt["receipt_id"],
                "evidence_ids": [
                    *current.payload["evidence_ids"],
                    evidence["evidence_id"],
                ],
                "provenance": receipt["provenance"],
                "observation": _plain(receipt["observation"]),
            })
        except ValueError as exc:
            raise CompanyChiefTakeoverError(
                "current Chief stop records are invalid",
            ) from exc
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                *_provider_lifecycle_drafts(receipt, evidence=evidence),
                CompanyEventDraft(
                    event_id=_current_chief_carrier_lost_event_id(
                        execution_id,
                        transaction_id=transaction_id,
                        command_id=command_id,
                    ),
                    event_type="carrier.current_chief.lost",
                    recorded_at=recorded_at,
                    payload=lost_carrier,
                    provenance=str(receipt["provenance"]),
                ),
                CompanyEventDraft(
                    event_id=_current_chief_execution_stop_event_id(
                        execution_id,
                        transaction_id=transaction_id,
                        command_id=command_id,
                    ),
                    event_type="execution.chief_current.stopped",
                    recorded_at=recorded_at,
                    payload=stopped,
                    provenance=str(receipt["provenance"]),
                ),
            ],
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _department_execution_status_result(
            committed.record,
            stopped,
            idempotent_replay=committed.idempotent_replay,
        )

    def stop_fenced_chief_execution(
        self,
        execution_id: str,
        provider_receipt: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExecutionRuntimeStatusResult:
        """Compatibility alias for the observation-recording API."""

        return self.record_fenced_chief_execution_stopped(
            execution_id,
            provider_receipt,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
        )

    def register_execution(
        self,
        execution: Mapping[str, Any],
        evidence: Mapping[str, Any],
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExecutionRuntimeStatusResult:
        """Register one provider-visible turn/agent/job without guessed lineage."""

        try:
            node = validate_execution_node(execution)
            observed = validate_evidence_record(evidence)
        except ValueError as exc:
            raise CompanyExecutionRegistrationError(
                "execution registration payload is invalid",
            ) from exc
        binding = self._binding()
        if {
            key: node[key]
            for key in (
                "company_id",
                "company_incarnation",
                "lock_domain_generation",
            )
        } != binding or {
            key: observed[key]
            for key in (
                "company_id",
                "company_incarnation",
                "lock_domain_generation",
            )
        } != binding:
            raise CompanyExecutionRegistrationError(
                "execution registration belongs to another company binding",
            )
        registration_id = node["registration_id"]
        if (
            registration_id is None
            or node["dispatch_id"] is not None
            or node["created_at"] != recorded_at
            or node["updated_at"] != recorded_at
            or node["last_event_at"] != recorded_at
            or node["provenance"] not in _PROVIDER_GRADE_PROVENANCE
            or node["observation"]["state"] == "unknown"
            or node["evidence_ids"] != [observed["evidence_id"]]
            or observed["execution_id"] != node["execution_id"]
            or observed["claim_id"] != registration_id
            or observed["evidence_class"] != "runtime"
            or observed["status"] != "observed"
            or observed["recorded_at"] != recorded_at
            or observed["artifact"]["media_type"]
            != EXECUTION_REGISTRATION_SOURCE_MEDIA_TYPE
            or observed["verification_sha256"]
            != observed["artifact"]["sha256"]
            or observed["provenance"] != node["provenance"]
            or observed["observation"] != node["observation"]
        ):
            raise CompanyExecutionRegistrationError(
                "execution registration evidence relation differs",
            )
        event = _execution_registration_event(node)
        current_event_id = _execution_registration_current_event_id(
            str(registration_id),
            str(node["execution_id"]),
        )
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _execution_registration_result_from_record(
                durable,
                node,
                observed,
                event,
                current_event_id=current_event_id,
                transaction_id=transaction_id,
                command_id=command_id,
                recorded_at=recorded_at,
                idempotent_replay=True,
            )
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                CompanyEventDraft(
                    event_id=str(observed["evidence_id"]),
                    event_type=(
                        "evidence.execution_registration.observed"
                    ),
                    recorded_at=recorded_at,
                    payload=observed,
                    provenance=str(observed["provenance"]),
                ),
                CompanyEventDraft(
                    event_id=str(registration_id),
                    event_type="execution.registered",
                    recorded_at=recorded_at,
                    payload=event,
                    provenance=str(node["provenance"]),
                ),
                CompanyEventDraft(
                    event_id=current_event_id,
                    event_type="execution.registered.current",
                    recorded_at=recorded_at,
                    payload=node,
                    provenance=str(node["provenance"]),
                ),
            ],
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _execution_registration_result_from_record(
            committed.record,
            node,
            observed,
            event,
            current_event_id=current_event_id,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            idempotent_replay=committed.idempotent_replay,
        )

    def queue_external_job(
        self,
        owner_execution_id: str,
        *,
        job_id: str,
        job_execution_id: str,
        mutation_intent_id: str,
        command_bytes: bytes,
        command_media_type: str,
        scope_sha256: str,
        display_name: str,
        objective: str,
        authority_grant_id: str,
        grant_expires_at: str,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExternalJobLifecycleResult:
        """Atomically attach one queued external job to its durable owner."""

        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _external_job_result_from_record(
                self._state,
                durable,
                job_id=job_id,
                expected_state="queued",
                owner_execution_id=owner_execution_id,
                job_execution_id=job_execution_id,
                mutation_intent_id=mutation_intent_id,
                transaction_id=transaction_id,
                command_id=command_id,
                recorded_at=recorded_at,
                expected_command_sha256=hashlib.sha256(
                    command_bytes,
                ).hexdigest(),
                expected_command_size=len(command_bytes),
                expected_command_media_type=command_media_type,
                expected_scope_sha256=scope_sha256,
                expected_display_name=display_name,
                expected_objective=objective,
                expected_authority_grant_id=authority_grant_id,
                expected_grant_expires_at=grant_expires_at,
                idempotent_replay=True,
            )
        owner = _current_payload(
            self._state,
            EXECUTION_NODE_V1,
            owner_execution_id,
        )
        if owner is None or owner["execution_kind"] not in {
            "carrier",
            "agent",
        }:
            raise CompanyExternalJobError(
                "external job owner execution is unavailable",
            )
        carrier_id = owner["carrier_id"]
        if carrier_id is None:
            raise CompanyExternalJobError(
                "external job owner has no provider carrier",
            )
        carrier = _current_payload(
            self._state,
            CARRIER_BINDING_V1,
            str(carrier_id),
        )
        if carrier is None:
            raise CompanyExternalJobError(
                "external job owner carrier is unavailable",
            )
        if (
            carrier["state"] != "active"
            or carrier["session_availability"] != "available"
            or owner["runtime_status"]
            not in {"running", "telemetry_silent", "unknown"}
            or owner["engineering_status"] in {"completed", "cancelled"}
            or owner["organization_node_id"] is None
            or job_id in owner["job_ids"]
        ):
            raise CompanyExternalJobError(
                "external job owner is not an active attributed execution",
            )
        if owner["execution_kind"] == "carrier":
            if (
                owner["role"] != "chief"
                or owner["department_id"] is not None
            ):
                raise CompanyExternalJobError(
                    "external job carrier owner is not the logical Chief",
                )
            actor_id = str(carrier["actor_id"])
            actor_kind = "chief"
            current_term, current_carrier, _chief_node_id = (
                self._current_chief_context()
            )
            if (
                current_carrier["carrier_id"] != carrier_id
                or current_term["carrier_id"] != carrier_id
            ):
                raise CompanyExternalJobError(
                    "external job Chief owner is fenced or stale",
                )
            term = int(current_term["term"])
            chief_epoch: int | None = int(current_term["epoch"])
        else:
            agent_id = owner["agent_id"]
            if agent_id is None:
                raise CompanyExternalJobError(
                    "external job agent owner identity is unavailable",
                )
            actor_id = str(agent_id)
            actor_kind = (
                "department_lead"
                if "lead" in str(owner["role"])
                else "worker"
            )
            term = 1
            chief_epoch = None
        binding = self._binding()
        current_grant = _current_payload(
            self._state,
            AUTHORITY_GRANT_V1,
            authority_grant_id,
        )
        if current_grant is None:
            grant = _authority_grant(
                binding,
                grant_id=authority_grant_id,
                actor_id=actor_id,
                actor_kind=actor_kind,
                carrier_id=str(carrier_id),
                chief_epoch=chief_epoch,
                term=term,
                permissions=["job.start"],
                scope_sha256=scope_sha256,
                bootstrap_at=recorded_at,
                grant_expires_at=grant_expires_at,
            )
            include_grant = True
        else:
            grant = current_grant
            include_grant = False
        try:
            grant = validate_authority_grant(grant)
        except ValueError as exc:
            raise CompanyExternalJobError(
                "external job authority grant is invalid",
            ) from exc
        if (
            grant["actor_id"] != actor_id
            or grant["actor_kind"] != actor_kind
            or grant["carrier_id"] != carrier_id
            or grant["scope_sha256"] != scope_sha256
            or grant["authority_state"] != "active"
            or "job.start" not in grant["permissions"]
            or grant["expires_at"] is None
            or _parsed_time(str(grant["expires_at"]))
            <= _parsed_time(recorded_at)
        ):
            raise CompanyExternalJobError(
                "external job authority differs from its owner or scope",
            )
        metadata = self._state.blobs.put(command_bytes)
        command_blob = {
            "contract_type": BLOB_REF_V1,
            "schema_version": 1,
            "sha256": metadata.sha256,
            "size_bytes": metadata.size_bytes,
            "media_type": command_media_type,
            "availability": "available",
        }
        authority = authority_from_grant(grant)
        heads = self.heads()
        owner_revision = validate_execution_node({
            **owner,
            "job_ids": [*owner["job_ids"], job_id],
            "updated_at": recorded_at,
            "last_event_at": recorded_at,
        })
        intent = validate_mutation_intent({
            "contract_type": MUTATION_INTENT_V1,
            "schema_version": 1,
            **binding,
            "intent_id": mutation_intent_id,
            "execution_id": owner_execution_id,
            "mutation_kind": "job.start",
            "command_id": command_id,
            "command_blob": command_blob,
            "scope_sha256": scope_sha256,
            "actor_authority": authority,
            "state": "admitted",
            "expected_head_sha256":
                heads.global_head.transaction_sha256,
            "created_at": recorded_at,
            "updated_at": recorded_at,
            "effect_evidence": [],
            "reconcile_ref": None,
            "observation": {"state": "known", "reason": "observed"},
        })
        job = validate_external_job({
            "contract_type": EXTERNAL_JOB_V1,
            "schema_version": 1,
            **binding,
            "job_id": job_id,
            "owner_execution_id": owner_execution_id,
            "mutation_intent_id": mutation_intent_id,
            "command_id": command_id,
            "command_blob": command_blob,
            "scope_sha256": scope_sha256,
            "actor_authority": authority,
            "state": "queued",
            "external_handle": None,
            "process_fingerprint_sha256": None,
            "process_observation": {
                "state": "unavailable",
                "reason": "not_started",
            },
            "created_at": recorded_at,
            "updated_at": recorded_at,
            "terminal_at": None,
            "effect_evidence": [],
            "reconcile_ref": None,
            "observation": {"state": "known", "reason": "observed"},
        })
        job_execution = _external_job_execution(
            owner,
            job,
            execution_id=job_execution_id,
            display_name=display_name,
            objective=objective,
        )
        execution_event = _external_job_execution_event(
            job_execution,
            job_state="queued",
            mutation_state="admitted",
            event_id=_external_job_event_id(
                transaction_id,
                "execution-event",
            ),
        )
        drafts: list[CompanyEventDraft] = []
        if include_grant:
            drafts.append(CompanyEventDraft(
                event_id=_external_job_event_id(
                    transaction_id,
                    "authority-grant",
                ),
                event_type="authority.granted",
                recorded_at=recorded_at,
                payload=grant,
            ))
        drafts.extend((
            CompanyEventDraft(
                event_id=_external_job_event_id(
                    transaction_id,
                    "owner-current",
                ),
                event_type="execution.external_job.attached",
                recorded_at=recorded_at,
                payload=owner_revision,
            ),
            CompanyEventDraft(
                event_id=_external_job_event_id(
                    transaction_id,
                    "execution-current",
                ),
                event_type="external_job.queued.current",
                recorded_at=recorded_at,
                payload=job_execution,
            ),
            CompanyEventDraft(
                event_id=str(execution_event["event_id"]),
                event_type="external_job.queued",
                recorded_at=recorded_at,
                payload=execution_event,
            ),
            CompanyEventDraft(
                event_id=_external_job_event_id(
                    transaction_id,
                    "mutation-intent",
                ),
                event_type="mutation_intent.admitted",
                recorded_at=recorded_at,
                payload=intent,
            ),
            CompanyEventDraft(
                event_id=_external_job_event_id(
                    transaction_id,
                    "job-current",
                ),
                event_type="external_job.queued",
                recorded_at=recorded_at,
                payload=job,
            ),
        ))
        request = build_company_transaction_request(
            heads,
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=drafts,
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _external_job_result_from_record(
            self._state,
            committed.record,
            job_id=job_id,
            expected_state="queued",
            owner_execution_id=owner_execution_id,
            job_execution_id=job_execution_id,
            mutation_intent_id=mutation_intent_id,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            expected_command_sha256=metadata.sha256,
            expected_command_size=metadata.size_bytes,
            expected_command_media_type=command_media_type,
            expected_scope_sha256=scope_sha256,
            expected_display_name=display_name,
            expected_objective=objective,
            expected_authority_grant_id=authority_grant_id,
            expected_grant_expires_at=grant_expires_at,
            idempotent_replay=committed.idempotent_replay,
        )

    def admit_external_job_launch(
        self,
        job_id: str,
        *,
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExternalJobLifecycleResult:
        """CAS one queued job into its single permitted launch attempt."""

        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _external_job_result_from_record(
                self._state,
                durable,
                job_id=job_id,
                expected_state="queued",
                expected_mutation_state="in_flight",
                transaction_id=transaction_id,
                command_id=command_id,
                recorded_at=recorded_at,
                idempotent_replay=True,
            )
        job = _required_current_external_job(self._state, job_id)
        intent = _required_current_job_intent(
            self._state,
            str(job["mutation_intent_id"]),
        )
        if job["state"] != "queued" or intent["state"] != "admitted":
            raise CompanyExternalJobError(
                "external job launch is not newly admissible",
            )
        if _parsed_time(recorded_at) <= _parsed_time(str(intent["updated_at"])):
            raise CompanyExternalJobError(
                "external job launch timestamp does not advance",
            )
        current = validate_mutation_intent({
            **intent,
            "state": "in_flight",
            "updated_at": recorded_at,
        })
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                CompanyEventDraft(
                    event_id=_external_job_event_id(
                        transaction_id,
                        "launch-intent",
                    ),
                    event_type="external_job.launch.admitted",
                    recorded_at=recorded_at,
                    payload=current,
                ),
            ],
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _external_job_result_from_record(
            self._state,
            committed.record,
            job_id=job_id,
            expected_state="queued",
            expected_mutation_state="in_flight",
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            idempotent_replay=committed.idempotent_replay,
        )

    def record_external_job_state(
        self,
        job_id: str,
        *,
        effect_source_bytes: bytes,
        external_handle: Mapping[str, Any] | None,
        effect_receipt: Mapping[str, Any],
        transaction_id: str,
        command_id: str,
        recorded_at: str,
    ) -> ExternalJobLifecycleResult:
        """Record one observed job transition without launching or retrying it."""

        receipt = self._external_job_effect_receipt(
            effect_receipt,
            source_bytes=effect_source_bytes,
        )
        state = str(receipt["observed_job_state"])
        if state not in {
            "running",
            "completed",
            "failed_known",
            "effect_unknown",
            "reconcile_required",
            "aborted",
        }:
            raise CompanyExternalJobError(
                "external job target state is unsupported",
            )
        mutation_state = _EXTERNAL_JOB_MUTATION_STATES[state]
        durable = self._state.record_by_transaction_id(transaction_id)
        if durable is not None:
            return _external_job_result_from_record(
                self._state,
                durable,
                job_id=job_id,
                expected_state=state,
                expected_mutation_state=mutation_state,
                expected_effect_receipt=receipt,
                expected_external_handle=external_handle,
                transaction_id=transaction_id,
                command_id=command_id,
                recorded_at=recorded_at,
                idempotent_replay=True,
            )
        prior = _required_current_external_job(self._state, job_id)
        prior_intent = _required_current_job_intent(
            self._state,
            str(prior["mutation_intent_id"]),
        )
        execution = _required_current_job_execution(
            self._state,
            job_id,
        )
        prior_state = str(prior["state"])
        self._bind_external_job_effect_receipt(
            receipt,
            job=prior,
            state=state,
            external_handle=external_handle,
            transaction_id=transaction_id,
            transition_command_id=command_id,
            recorded_at=recorded_at,
        )
        if (
            state
            not in _EXTERNAL_JOB_ALLOWED_TRANSITIONS.get(
                prior_state,
                frozenset(),
            )
            or prior_intent["state"]
            not in _EXTERNAL_JOB_PRIOR_INTENT_STATES.get(
                (prior_state, state),
                frozenset(),
            )
            or _parsed_time(recorded_at)
            <= _parsed_time(str(prior["updated_at"]))
            or _parsed_time(recorded_at)
            <= _parsed_time(str(prior_intent["updated_at"]))
        ):
            raise CompanyExternalJobError(
                "external job lifecycle transition is not admissible",
            )
        normalized_handle = (
            None
            if external_handle is None
            else _plain(external_handle)
        )
        process_observation = (
            {
                "state": "unavailable",
                "reason": "aborted_before_launch",
            }
            if state == "aborted"
            else _plain(receipt["observation"])
        )
        effect_evidence = [
            *_plain(prior["effect_evidence"]),
            *(
                [_plain(receipt["raw_artifact"])]
                if state not in {"running", "aborted"}
                else []
            ),
        ]
        reconcile_ref = (
            receipt["reconciliation_id"]
            if state in {"effect_unknown", "reconcile_required"}
            else None
        )
        expected_job_fields = {
            "external_handle": normalized_handle,
            "process_fingerprint_sha256":
                receipt["process_fingerprint_sha256"],
            "process_observation": process_observation,
            "effect_evidence": effect_evidence,
            "reconcile_ref": reconcile_ref,
            "observation": _plain(receipt["observation"]),
        }
        terminal_at = (
            recorded_at
            if state in {"completed", "failed_known", "aborted"}
            else None
        )
        job = validate_external_job({
            **prior,
            "state": state,
            "external_handle": expected_job_fields["external_handle"],
            "process_fingerprint_sha256":
                expected_job_fields["process_fingerprint_sha256"],
            "process_observation":
                expected_job_fields["process_observation"],
            "updated_at": recorded_at,
            "terminal_at": terminal_at,
            "effect_evidence": expected_job_fields["effect_evidence"],
            "reconcile_ref": reconcile_ref,
            "observation": receipt["observation"],
        })
        intent = validate_mutation_intent({
            **prior_intent,
            "state": mutation_state,
            "updated_at": recorded_at,
            "effect_evidence": job["effect_evidence"],
            "reconcile_ref": reconcile_ref,
            "observation": receipt["observation"],
        })
        job_execution = _external_job_execution_revision(
            execution,
            job,
        )
        execution_event = _external_job_execution_event(
            job_execution,
            job_state=state,
            mutation_state=mutation_state,
            event_id=_external_job_event_id(
                transaction_id,
                "execution-event",
            ),
        )
        metadata = self._state.blobs.put(effect_source_bytes)
        if (
            metadata.sha256 != receipt["raw_artifact"]["sha256"]
            or metadata.size_bytes != receipt["raw_artifact"]["size_bytes"]
        ):
            raise CompanyExternalJobError(
                "external job effect source storage differs",
            )
        request = build_company_transaction_request(
            self.heads(),
            self._supervisor_authority(),
            transaction_id=transaction_id,
            command_id=command_id,
            events=[
                _external_job_effect_draft(receipt),
                CompanyEventDraft(
                    event_id=_external_job_event_id(
                        transaction_id,
                        "execution-current",
                    ),
                    event_type=f"external_job.{state}.current",
                    recorded_at=recorded_at,
                    payload=job_execution,
                ),
                CompanyEventDraft(
                    event_id=str(execution_event["event_id"]),
                    event_type=f"external_job.{state}",
                    recorded_at=recorded_at,
                    payload=execution_event,
                ),
                CompanyEventDraft(
                    event_id=_external_job_event_id(
                        transaction_id,
                        "mutation-intent",
                    ),
                    event_type=f"mutation_intent.{mutation_state}",
                    recorded_at=recorded_at,
                    payload=intent,
                ),
                CompanyEventDraft(
                    event_id=_external_job_event_id(
                        transaction_id,
                        "job-current",
                    ),
                    event_type=f"external_job.{state}",
                    recorded_at=recorded_at,
                    payload=job,
                ),
            ],
        )
        committed = self.commit(request, recorded_at=recorded_at)
        return _external_job_result_from_record(
            self._state,
            committed.record,
            job_id=job_id,
            expected_state=state,
            expected_mutation_state=mutation_state,
            expected_job_fields=expected_job_fields,
            expected_effect_receipt=receipt,
            expected_external_handle=external_handle,
            transaction_id=transaction_id,
            command_id=command_id,
            recorded_at=recorded_at,
            idempotent_replay=committed.idempotent_replay,
        )

    def prepare_chief_takeover(
        self,
        known_carrier: Mapping[str, Any],
        *,
        user_action_ref: str,
        objective_sha256: str,
        scope_sha256: str,
        nonce_sha256: str,
        issued_at: str,
        expires_at: str,
    ) -> dict[str, Any]:
        """Create a head-bound, one-shot capability from fresh user intent.

        Preparation does not mutate the ledger.  The returned capability binds
        its only transaction/command IDs and a digest-derived carrier
        observation; a later head drift therefore fences rather than refreshes
        the user intent.
        """

        binding = self._binding()
        term, _current_carrier, _chief_node_id = (
            self._current_chief_context()
        )
        try:
            contender = _carrier_payload(
                binding,
                actor_id=str(term["chief_id"]),
                carrier_id=str(known_carrier.get("carrier_id", "")),
                bootstrap_at=issued_at,
                known_carrier=known_carrier,
            )
        except CompanySupervisorError as exc:
            raise CompanyChiefTakeoverError(
                "takeover contender carrier is invalid",
            ) from exc
        if contender["carrier_id"] == term["carrier_id"]:
            raise CompanyChiefTakeoverError(
                "takeover contender is already the current Chief carrier",
            )
        existing = {
            str(item.payload["carrier_id"]): _plain(item.payload)
            for item in self.objects(contract_type=CARRIER_BINDING_V1)
        }.get(str(contender["carrier_id"]))
        if existing is not None:
            raise CompanyChiefTakeoverError(
                "takeover contender must use a new durable carrier ID",
            )
        heads = self.heads()
        seed = _takeover_seed(
            binding,
            known_carrier,
            expected_chief_id=str(term["chief_id"]),
            expected_term=int(term["term"]),
            expected_epoch=int(term["epoch"]),
            expected_head_sha256=heads.global_head.transaction_sha256,
            objective_sha256=objective_sha256,
            scope_sha256=scope_sha256,
            nonce_sha256=nonce_sha256,
            issued_at=issued_at,
            expires_at=expires_at,
            user_action_ref=user_action_ref,
        )
        ids = _takeover_ids(seed)
        unsigned = {
            "contract_type": TAKEOVER_CAPABILITY_V1,
            "schema_version": 1,
            **binding,
            "capability_id": ids["capability"],
            "contender_carrier_id": contender["carrier_id"],
            "expected_chief_id": term["chief_id"],
            "expected_term": term["term"],
            "expected_epoch": term["epoch"],
            "expected_head_sha256":
                heads.global_head.transaction_sha256,
            "consumption_id": ids["consumption"],
            "consumption_transaction_id": ids["transaction"],
            "consumption_command_id": ids["command"],
            "resulting_chief_id": term["chief_id"],
            "resulting_term": int(term["term"]) + 1,
            "resulting_epoch": int(term["epoch"]) + 1,
            "objective_sha256": objective_sha256,
            "scope_sha256": scope_sha256,
            "nonce_sha256": nonce_sha256,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "user_action_ref": user_action_ref,
        }
        try:
            return validate_takeover_capability({
                **unsigned,
                "capability_sha256": company_contract_sha256(unsigned),
            })
        except ValueError as exc:
            raise CompanyChiefTakeoverError(
                "fresh user takeover capability is invalid",
            ) from exc

    def takeover_chief(
        self,
        capability: Mapping[str, Any],
        known_carrier: Mapping[str, Any],
        *,
        consumed_at: str,
        grant_expires_at: str,
    ) -> ChiefTakeoverResult:
        """Consume a one-shot capability as winner or durable fenced loser."""

        try:
            normalized = validate_takeover_capability(capability)
        except ValueError as exc:
            raise CompanyChiefTakeoverError(
                "takeover capability is invalid",
            ) from exc
        if {
            key: normalized[key]
            for key in (
                "company_id",
                "company_incarnation",
                "lock_domain_generation",
            )
        } != self._binding():
            raise CompanyChiefTakeoverError(
                "takeover capability belongs to another company binding",
            )
        expected_ids = _takeover_ids(
            _takeover_seed(
                self._binding(),
                known_carrier,
                expected_chief_id=str(normalized["expected_chief_id"]),
                expected_term=int(normalized["expected_term"]),
                expected_epoch=int(normalized["expected_epoch"]),
                expected_head_sha256=str(
                    normalized["expected_head_sha256"],
                ),
                objective_sha256=str(normalized["objective_sha256"]),
                scope_sha256=str(normalized["scope_sha256"]),
                nonce_sha256=str(normalized["nonce_sha256"]),
                issued_at=str(normalized["issued_at"]),
                expires_at=str(normalized["expires_at"]),
                user_action_ref=str(normalized["user_action_ref"]),
            ),
        )
        if (
            normalized["capability_id"] != expected_ids["capability"]
            or normalized["consumption_id"] != expected_ids["consumption"]
            or normalized["consumption_transaction_id"]
            != expected_ids["transaction"]
            or normalized["consumption_command_id"]
            != expected_ids["command"]
        ):
            raise CompanyChiefTakeoverError(
                "takeover capability does not bind this carrier observation",
            )
        durable = self._state.record_by_transaction_id(
            str(normalized["consumption_transaction_id"]),
        )
        if durable is not None:
            return self._takeover_result_from_record(
                durable,
                normalized,
                known_carrier,
                consumed_at=consumed_at,
                grant_expires_at=grant_expires_at,
                expected_ids=expected_ids,
                idempotent_replay=True,
            )

        binding = self._binding()
        term, prior_carrier, chief_node_id = self._current_chief_context()
        heads = self.heads()
        can_consume = (
            heads.global_head.transaction_sha256
            == normalized["expected_head_sha256"]
            and term["chief_id"] == normalized["expected_chief_id"]
            and term["term"] == normalized["expected_term"]
            and term["epoch"] == normalized["expected_epoch"]
        )
        outcome = "consumed" if can_consume else "fenced"
        resulting = None
        prior_execution_fence: dict[str, Any] | None = None
        unknown_genesis_first_bind = False
        if outcome == "consumed":
            prior_executions = [
                _plain(item.payload)
                for item in self.objects(contract_type=EXECUTION_NODE_V1)
                if (
                    item.payload["role"] == "chief"
                    and item.payload["carrier_id"] == prior_carrier["carrier_id"]
                    and item.payload["parent_execution_id"] is None
                )
            ]
            unknown_genesis_first_bind = (
                term["term"] == 1
                and term["epoch"] == 1
                and term["takeover_capability_sha256"] is None
                and term[
                    "takeover_consumption_receipt_sha256"
                ] is None
                and self._unknown_genesis_carrier_matches(
                    prior_carrier,
                    chief_id=str(term["chief_id"]),
                    state="unknown",
                )
            )
            if len(prior_executions) == 0 and unknown_genesis_first_bind:
                prior_execution_fence = None
            elif len(prior_executions) != 1:
                raise CompanyChiefTakeoverError(
                    "takeover cannot identify one prior Chief execution",
                )
            else:
                if unknown_genesis_first_bind:
                    raise CompanyChiefTakeoverError(
                        "unknown genesis Chief cannot have a prior execution",
                    )
                if _parsed_time(consumed_at) < _parsed_time(
                    str(prior_executions[0]["updated_at"]),
                ):
                    raise CompanyChiefTakeoverError(
                        "takeover consumption predates the prior Chief execution",
                    )
                prior_execution_revision = {
                    **prior_executions[0],
                    "updated_at": consumed_at,
                    "last_event_at": consumed_at,
                }
                if (
                    prior_executions[0]["runtime_status"]
                    in {"running", "telemetry_silent", "unknown"}
                    and prior_executions[0]["engineering_status"]
                    not in {"completed", "cancelled"}
                ):
                    prior_execution_revision.update({
                        "engineering_status": "waiting",
                        "wait_reason": "fenced_read_only",
                    })
                try:
                    prior_execution_fence = validate_execution_node(
                        prior_execution_revision,
                    )
                except ValueError as exc:
                    raise CompanyChiefTakeoverError(
                        "prior Chief execution cannot be durably fenced",
                    ) from exc
            resulting_unsigned = {
                "chief_id": normalized["resulting_chief_id"],
                "carrier_id": normalized["contender_carrier_id"],
                "term": normalized["resulting_term"],
                "epoch": normalized["resulting_epoch"],
                "takeover_capability_sha256":
                    normalized["capability_sha256"],
            }
            resulting = {
                **resulting_unsigned,
                "chief_term_sha256": company_contract_sha256(
                    resulting_unsigned,
                ),
            }
        receipt_unsigned = {
            "contract_type": TAKEOVER_CONSUMPTION_RECEIPT_V1,
            "schema_version": 1,
            **binding,
            "consumption_id": normalized["consumption_id"],
            "transaction_id":
                normalized["consumption_transaction_id"],
            "command_id": normalized["consumption_command_id"],
            "capability": _plain(normalized),
            "capability_sha256": normalized["capability_sha256"],
            "outcome": outcome,
            "resulting_chief_term": resulting,
            "consumed_at": consumed_at,
        }
        try:
            takeover_receipt = validate_takeover_consumption_receipt({
                **receipt_unsigned,
                "receipt_sha256": company_contract_sha256(
                    receipt_unsigned,
                ),
            })
            contender = _carrier_payload(
                binding,
                actor_id=str(normalized["resulting_chief_id"]),
                carrier_id=str(normalized["contender_carrier_id"]),
                bootstrap_at=consumed_at,
                known_carrier=known_carrier,
            )
        except ValueError as exc:
            raise CompanyChiefTakeoverError(
                "takeover consumption or contender observation is invalid",
            ) from exc

        if outcome == "fenced":
            contender = validate_carrier_binding({
                **contender,
                "state": "fenced",
            })
        ids = expected_ids
        payloads: list[tuple[str, str, Mapping[str, Any], str]] = [
            (
                "capability",
                "chief.takeover.capability.consumed",
                normalized,
                "AOI_verified",
            ),
            (
                "receipt",
                f"chief.takeover.{outcome}",
                takeover_receipt,
                "AOI_verified",
            ),
        ]
        if outcome == "consumed":
            if (
                prior_execution_fence is None
                and not unknown_genesis_first_bind
            ):
                raise CompanyChiefTakeoverError(
                    "takeover lacks its prior Chief execution fence",
                )
            if unknown_genesis_first_bind:
                prior_fence = validate_carrier_binding({
                    **prior_carrier,
                    "state": "fenced",
                })
            else:
                prior_fence = validate_carrier_binding({
                    **prior_carrier,
                    "state": "fenced",
                    "last_observed_at": consumed_at,
                    "observation": {
                        "state": "known",
                        "reason": "observed",
                    },
                })
            try:
                new_grant = validate_authority_grant(_authority_grant(
                    binding,
                    grant_id=ids["grant"],
                    actor_id=str(normalized["resulting_chief_id"]),
                    actor_kind="chief",
                    carrier_id=str(normalized["contender_carrier_id"]),
                    chief_epoch=int(normalized["resulting_epoch"]),
                    term=int(normalized["resulting_term"]),
                    permissions=["company.mutate"],
                    scope_sha256=str(normalized["scope_sha256"]),
                    bootstrap_at=consumed_at,
                    grant_expires_at=grant_expires_at,
                ))
            except ValueError as exc:
                raise CompanyChiefTakeoverError(
                    "takeover Chief authority grant is invalid",
                ) from exc
            new_term = {
                "contract_type": CHIEF_TERM_V1,
                "schema_version": 1,
                **binding,
                "chief_id": normalized["resulting_chief_id"],
                "carrier_id": normalized["contender_carrier_id"],
                "term": normalized["resulting_term"],
                "epoch": normalized["resulting_epoch"],
                "state": "active",
                "issued_at": consumed_at,
                "ended_at": None,
                "previous_transaction_sha256":
                    heads.global_head.transaction_sha256,
                "takeover_capability_sha256":
                    normalized["capability_sha256"],
                "takeover_consumption_receipt_sha256":
                    takeover_receipt["receipt_sha256"],
                "observation": {
                    "state": "known",
                    "reason": "observed",
                },
            }
            payloads.extend((
                (
                    "term",
                    "chief.term.advanced",
                    new_term,
                    "AOI_verified",
                ),
                (
                    "grant",
                    "authority.granted",
                    new_grant,
                    "AOI_verified",
                ),
                (
                    "prior-carrier",
                    "carrier.fenced",
                    prior_fence,
                    "AOI_verified",
                ),
            ))
            if prior_execution_fence is not None:
                payloads.append((
                    "prior-execution",
                    "execution.authority_fenced",
                    prior_execution_fence,
                    "AOI_verified",
                ))
            payloads.append((
                "contender-carrier",
                "carrier.bound",
                contender,
                "agent_reported",
            ))
        else:
            payloads.append((
                "contender-carrier",
                "carrier.fenced",
                contender,
                "agent_reported",
            ))
        payloads.append((
            "execution",
            "execution.created",
            _chief_execution_node(
                binding,
                execution_id=ids["execution"],
                chief_node_id=chief_node_id,
                carrier=contender,
                thread_id=str(known_carrier["thread_id"]),
                provenance="agent_reported",
                bootstrap_at=consumed_at,
                engineering_status=(
                    "active" if outcome == "consumed" else "waiting"
                ),
                phase="handoff",
                wait_reason=(
                    None if outcome == "consumed" else "fenced_read_only"
                ),
            ),
            "agent_reported",
        ))
        request = build_company_transaction_request(
            heads,
            self._supervisor_authority(),
            transaction_id=str(
                normalized["consumption_transaction_id"],
            ),
            command_id=str(normalized["consumption_command_id"]),
            events=[
                CompanyEventDraft(
                    event_id=ids[f"{suffix}_event"],
                    event_type=event_type,
                    recorded_at=consumed_at,
                    payload=payload,
                    provenance=provenance,
                )
                for suffix, event_type, payload, provenance in payloads
            ],
        )
        result = self.commit(request, recorded_at=consumed_at)
        return self._takeover_result_from_record(
            result.record,
            normalized,
            known_carrier,
            consumed_at=consumed_at,
            grant_expires_at=grant_expires_at,
            expected_ids=expected_ids,
            idempotent_replay=result.idempotent_replay,
        )

    def _takeover_result_from_record(
        self,
        record: LedgerTransactionRecord,
        capability: Mapping[str, Any],
        known_carrier: Mapping[str, Any],
        *,
        consumed_at: str,
        grant_expires_at: str,
        expected_ids: Mapping[str, str],
        idempotent_replay: bool,
    ) -> ChiefTakeoverResult:
        members = record.events if record.events else record.reservations
        wrappers = [_plain(member.event) for member in members]
        payloads = [wrapper["payload"] for wrapper in wrappers]
        capabilities = [
            value for value in payloads
            if value.get("contract_type") == TAKEOVER_CAPABILITY_V1
        ]
        receipts = [
            value for value in payloads
            if value.get("contract_type")
            == TAKEOVER_CONSUMPTION_RECEIPT_V1
        ]
        if (
            len(capabilities) != 1
            or len(receipts) != 1
            or capabilities[0] != _plain(capability)
        ):
            raise CompanyChiefTakeoverError(
                "durable takeover replay differs from its capability",
            )
        receipt = receipts[0]
        if (
            receipt["consumed_at"] != consumed_at
            or receipt["transaction_id"]
            != capability["consumption_transaction_id"]
            or receipt["command_id"]
            != capability["consumption_command_id"]
        ):
            raise CompanyChiefTakeoverError(
                "takeover retry differs from the durable consumption",
        )
        outcome = str(receipt["outcome"])
        durable_event_ids = {
            str(wrapper["event_id"]) for wrapper in wrappers
        }
        expected_envelopes = {
            str(expected_ids["capability_event"]): (
                "org",
                "chief.takeover.capability.consumed",
                "AOI_verified",
            ),
            str(expected_ids["receipt_event"]): (
                "org",
                f"chief.takeover.{outcome}",
                "AOI_verified",
            ),
            str(expected_ids["contender-carrier_event"]): (
                "org",
                (
                    "carrier.bound"
                    if outcome == "consumed"
                    else "carrier.fenced"
                ),
                "agent_reported",
            ),
            str(expected_ids["execution_event"]): (
                "execution",
                "execution.created",
                "agent_reported",
            ),
        }
        if outcome == "consumed":
            expected_envelopes.update({
                str(expected_ids["term_event"]): (
                    "org",
                    "chief.term.advanced",
                    "AOI_verified",
                ),
                str(expected_ids["grant_event"]): (
                    "org",
                    "authority.granted",
                    "AOI_verified",
                ),
                str(expected_ids["prior-carrier_event"]): (
                    "org",
                    "carrier.fenced",
                    "AOI_verified",
                ),
            })
            if (
                str(expected_ids["prior-execution_event"])
                in durable_event_ids
            ):
                expected_envelopes[
                    str(expected_ids["prior-execution_event"])
                ] = (
                    "execution",
                    "execution.authority_fenced",
                    "AOI_verified",
                )
        wrappers_by_id = {
            str(wrapper["event_id"]): wrapper for wrapper in wrappers
        }
        if set(wrappers_by_id) != set(expected_envelopes):
            raise CompanyChiefTakeoverError(
                "durable takeover event membership differs",
            )
        for event_id, (stream, event_type, provenance) in (
            expected_envelopes.items()
        ):
            wrapper = wrappers_by_id[event_id]
            if (
                wrapper["stream"] != stream
                or wrapper["event_type"] != event_type
                or wrapper["provenance"] != provenance
                or wrapper["recorded_at"] != consumed_at
            ):
                raise CompanyChiefTakeoverError(
                    "durable takeover event envelope differs",
                )
        carriers = [
            value for value in payloads
            if (
                value.get("contract_type") == CARRIER_BINDING_V1
                and value.get("carrier_id")
                == capability["contender_carrier_id"]
            )
        ]
        executions = [
            value for value in payloads
            if (
                value.get("contract_type") == EXECUTION_NODE_V1
                and value.get("carrier_id")
                == capability["contender_carrier_id"]
            )
        ]
        if len(carriers) != 1 or len(executions) != 1:
            raise CompanyChiefTakeoverError(
                "durable takeover lacks its contender lifecycle",
            )
        carrier, execution = carriers[0], executions[0]
        binding = {
            key: capability[key]
            for key in (
                "company_id",
                "company_incarnation",
                "lock_domain_generation",
            )
        }
        expected_carrier = _carrier_payload(
            binding,
            actor_id=str(capability["resulting_chief_id"]),
            carrier_id=str(capability["contender_carrier_id"]),
            bootstrap_at=consumed_at,
            known_carrier=known_carrier,
        )
        if outcome == "fenced":
            expected_carrier = validate_carrier_binding({
                **expected_carrier,
                "state": "fenced",
            })
        if carrier != expected_carrier:
            raise CompanyChiefTakeoverError(
                "takeover retry carrier differs from durable bytes",
            )
        expected_execution = _chief_execution_node(
            binding,
            execution_id=str(expected_ids["execution"]),
            chief_node_id=str(execution["organization_node_id"]),
            carrier=expected_carrier,
            thread_id=str(known_carrier["thread_id"]),
            provenance="agent_reported",
            bootstrap_at=consumed_at,
            engineering_status=(
                "active" if outcome == "consumed" else "waiting"
            ),
            phase="handoff",
            wait_reason=(
                None if outcome == "consumed" else "fenced_read_only"
            ),
        )
        if execution != expected_execution:
            raise CompanyChiefTakeoverError(
                "takeover retry execution differs from durable bytes",
            )
        if outcome == "consumed":
            prior_carriers = [
                value for value in payloads
                if (
                    value.get("contract_type") == CARRIER_BINDING_V1
                    and value.get("carrier_id")
                    != capability["contender_carrier_id"]
                )
            ]
            prior_executions = [
                value for value in payloads
                if (
                    value.get("contract_type") == EXECUTION_NODE_V1
                    and value.get("carrier_id")
                    != capability["contender_carrier_id"]
                )
            ]
            prior_execution_event_present = (
                str(expected_ids["prior-execution_event"])
                in wrappers_by_id
            )
            if len(prior_carriers) != 1:
                raise CompanyChiefTakeoverError(
                    "durable takeover lacks its prior carrier fence",
                )
            unknown_genesis_first_bind = (
                capability["expected_term"] == 1
                and capability["expected_epoch"] == 1
                and self._unknown_genesis_carrier_matches(
                    prior_carriers[0],
                    chief_id=str(capability["expected_chief_id"]),
                    state="fenced",
                )
            )
            if unknown_genesis_first_bind:
                if prior_executions or prior_execution_event_present:
                    raise CompanyChiefTakeoverError(
                        "unknown genesis takeover fabricated a prior execution",
                    )
            elif (
                len(prior_executions) != 1
                or not prior_execution_event_present
                or prior_carriers[0]["state"] != "fenced"
                or prior_carriers[0]["observation"]["state"] != "known"
                or prior_executions[0]["carrier_id"]
                != prior_carriers[0]["carrier_id"]
                or prior_executions[0]["updated_at"] != consumed_at
                or prior_executions[0]["last_event_at"] != consumed_at
                or (
                    prior_executions[0]["runtime_status"]
                    in {"running", "telemetry_silent", "unknown"}
                    and (
                        prior_executions[0]["engineering_status"]
                        != "waiting"
                        or prior_executions[0]["wait_reason"]
                        != "fenced_read_only"
                    )
                )
            ):
                raise CompanyChiefTakeoverError(
                    "durable takeover lacks its prior execution fence",
                )
            grants = [
                value for value in payloads
                if (
                    value.get("contract_type") == AUTHORITY_GRANT_V1
                    and value.get("actor_kind") == "chief"
                    and value.get("term") == capability["resulting_term"]
                    and value.get("chief_epoch")
                    == capability["resulting_epoch"]
                )
            ]
            if (
                len(grants) != 1
                or grants[0]["expires_at"] != grant_expires_at
            ):
                raise CompanyChiefTakeoverError(
                    "takeover retry grant differs from durable bytes",
                )
        return ChiefTakeoverResult(
            outcome=outcome,
            receipt_state=str(record.receipt["state"]),
            capability_id=str(capability["capability_id"]),
            consumption_id=str(capability["consumption_id"]),
            transaction_id=str(record.request["transaction_id"]),
            command_id=str(record.request["command_id"]),
            chief_id=str(capability["resulting_chief_id"]),
            carrier_id=str(capability["contender_carrier_id"]),
            term=(
                int(capability["resulting_term"])
                if outcome == "consumed"
                else None
            ),
            epoch=(
                int(capability["resulting_epoch"])
                if outcome == "consumed"
                else None
            ),
            global_sequence=record.global_sequence,
            idempotent_replay=idempotent_replay,
        )

    @property
    def dashboard_url(self) -> str | None:
        """Return the active local Command Center URL, if started."""

        server = self._dashboard_server
        return None if server is None else server.url

    def start_dashboard(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        environment_kind: str = "unverified",
    ) -> str:
        """Publish an owner-thread snapshot, then start the cache-only server."""

        cache = self._dashboard_cache
        server = self._dashboard_server
        if cache is not None or server is not None:
            if cache is None or server is None:
                raise CompanySupervisorError(
                    "Dashboard lifecycle is internally inconsistent",
                )
            if self._dashboard_environment_kind != environment_kind:
                raise CompanySupervisorError(
                    "Dashboard environment differs from the active server",
                )
            cache.refresh()
            return server.start()
        cache = CompanyDashboardSnapshotCache(
            CompanyViewService(
                self._state,
                environment_kind=environment_kind,
            ),
        )
        cache.refresh()
        server = CompanyDashboardServer(cache, host=host, port=port)
        try:
            url = server.start()
        except BaseException:
            server.close()
            raise
        self._dashboard_cache = cache
        self._dashboard_server = server
        self._dashboard_environment_kind = environment_kind
        return url

    def refresh_dashboard(self) -> int:
        """Publish the latest projection from the Supervisor owner thread."""

        cache = self._dashboard_cache
        if cache is None or self._dashboard_server is None:
            raise CompanySupervisorError("Dashboard is not started")
        return cache.refresh()

    @classmethod
    def initialize(
        cls,
        slot_root: str | os.PathLike[str],
        manifest: Mapping[str, Any],
        *,
        bootstrap_at: str,
        grant_expires_at: str,
        platform: str,
        known_carrier: Mapping[str, Any] | None = None,
        lock_timeout_seconds: float = 5.0,
    ) -> Self:
        """Open one owner and commit genesis once for an empty incarnation.

        Repeating this call with the same manifest and bootstrap inputs is safe:
        the registry requires identical manifest bytes and a nonempty ledger is
        never given another genesis transaction.
        """

        normalized_manifest = validate_company_manifest(manifest)
        if normalized_manifest["created_at"] != bootstrap_at:
            raise CompanySupervisorError(
                "bootstrap time differs from the company manifest",
            )
        binding = {
            "company_id": normalized_manifest["company_id"],
            "company_incarnation": normalized_manifest[
                "company_incarnation"
            ],
            "lock_domain_generation": normalized_manifest[
                "lock_domain_generation"
            ],
        }
        ids = _genesis_ids(
            str(binding["company_id"]),
            int(binding["company_incarnation"]),
            int(binding["lock_domain_generation"]),
        )
        carrier = _carrier_payload(
            binding,
            actor_id=ids["chief"],
            carrier_id=ids["chief_carrier"],
            bootstrap_at=bootstrap_at,
            known_carrier=known_carrier,
        )
        try:
            validate_authority_grant(
                _authority_grant(
                    binding,
                    grant_id=ids["supervisor_grant"],
                    actor_id=ids["supervisor"],
                    actor_kind="supervisor",
                    carrier_id=None,
                    chief_epoch=None,
                    permissions=["company.mutate"],
                    bootstrap_at=bootstrap_at,
                    grant_expires_at=grant_expires_at,
                ),
            )
            validate_authority_grant(
                _authority_grant(
                    binding,
                    grant_id=ids["chief_grant"],
                    actor_id=ids["chief"],
                    actor_kind="chief",
                    carrier_id=str(carrier["carrier_id"]),
                    chief_epoch=1,
                    permissions=["company.mutate"],
                    bootstrap_at=bootstrap_at,
                    grant_expires_at=grant_expires_at,
                ),
            )
        except ValueError as exc:
            raise CompanySupervisorError(
                "bootstrap authority grant is invalid",
            ) from exc
        state = CompanyStateOwner.initialize(
            slot_root,
            normalized_manifest,
            platform=platform,
            lock_timeout_seconds=lock_timeout_seconds,
        )
        supervisor = cls(state)
        try:
            supervisor._bootstrap(
                bootstrap_at=bootstrap_at,
                grant_expires_at=grant_expires_at,
                known_carrier=known_carrier,
            )
        except BaseException:
            supervisor.close()
            raise
        return supervisor

    @classmethod
    def open(
        cls,
        slot_root: str | os.PathLike[str],
        *,
        lock_timeout_seconds: float = 5.0,
    ) -> Self:
        """Reopen an existing incarnation without manufacturing lifecycle facts."""

        state = CompanyStateOwner.open(
            slot_root,
            lock_timeout_seconds=lock_timeout_seconds,
        )
        supervisor = cls(state)
        try:
            supervisor._validate_genesis()
        except BaseException:
            supervisor.close()
            raise
        return supervisor

    def _bootstrap(
        self,
        *,
        bootstrap_at: str,
        grant_expires_at: str,
        known_carrier: Mapping[str, Any] | None,
    ) -> None:
        heads = self._state.heads()
        if heads.global_head.global_sequence != 0:
            self._validate_genesis(
                bootstrap_at=bootstrap_at,
                grant_expires_at=grant_expires_at,
                known_carrier=known_carrier,
            )
            return

        manifest = validate_company_manifest(self._state.resolved.manifest)
        company_id = str(manifest["company_id"])
        incarnation = int(manifest["company_incarnation"])
        generation = int(manifest["lock_domain_generation"])
        binding = {
            "company_id": company_id,
            "company_incarnation": incarnation,
            "lock_domain_generation": generation,
        }
        ids = _genesis_ids(company_id, incarnation, generation)
        supervisor_grant = _authority_grant(
            binding,
            grant_id=ids["supervisor_grant"],
            actor_id=ids["supervisor"],
            actor_kind="supervisor",
            carrier_id=None,
            chief_epoch=None,
            permissions=["company.mutate"],
            bootstrap_at=bootstrap_at,
            grant_expires_at=grant_expires_at,
        )
        carrier = _carrier_payload(
            binding,
            actor_id=ids["chief"],
            carrier_id=ids["chief_carrier"],
            bootstrap_at=bootstrap_at,
            known_carrier=known_carrier,
        )
        chief_carrier_id = carrier["carrier_id"]
        chief_grant = _authority_grant(
            binding,
            grant_id=ids["chief_grant"],
            actor_id=ids["chief"],
            actor_kind="chief",
            carrier_id=chief_carrier_id,
            chief_epoch=1,
            permissions=["company.mutate"],
            bootstrap_at=bootstrap_at,
            grant_expires_at=grant_expires_at,
        )
        authority = authority_from_grant(supervisor_grant)
        chief_node_id = ids["chief_node"]
        departments = ("rtl", "dv", "pd")
        department_nodes = {
            department: ids[f"{department}_lead_node"]
            for department in departments
        }
        department_ids = {
            department: ids[f"{department}_department"]
            for department in departments
        }
        department_snapshots: dict[str, dict[str, Any]] = {}
        for department in departments:
            snapshot, _document, resources = (
                _genesis_department_snapshot_material(
                    binding,
                    department=department,
                    department_id=department_ids[department],
                    lead_node_id=department_nodes[department],
                    bootstrap_at=bootstrap_at,
                )
            )
            for reference, raw in resources:
                metadata = self._state.blobs.put(raw)
                if (
                    metadata.sha256 != reference["sha256"]
                    or metadata.size_bytes != reference["size_bytes"]
                ):
                    raise CompanySupervisorError(
                        "genesis department resource publication differs",
                    )
            department_snapshots[department] = snapshot
        payloads: list[tuple[str, str, Mapping[str, Any], str]] = [
            ("manifest", "manifest.recorded", manifest, "AOI_verified"),
            (
                "supervisor-grant",
                "authority.granted",
                supervisor_grant,
                "AOI_verified",
            ),
            ("chief-grant", "authority.granted", chief_grant, "AOI_verified"),
            (
                "chief-node",
                "organization.created",
                _organization_node(
                    binding,
                    node_id=chief_node_id,
                    department_id=None,
                    parent_node_id=None,
                    role="chief",
                    reports_to_node_id=None,
                    delegation_depth=0,
                    bootstrap_at=bootstrap_at,
                ),
                "AOI_verified",
            ),
        ]
        for department in departments:
            department_id = department_ids[department]
            lead_node_id = department_nodes[department]
            payloads.extend(
                (
                    (
                        f"{department}-lead-node",
                        "organization.created",
                        _organization_node(
                            binding,
                            node_id=lead_node_id,
                            department_id=department_id,
                            parent_node_id=chief_node_id,
                            role=f"{department}_lead",
                            reports_to_node_id=chief_node_id,
                            delegation_depth=1,
                            status="parked",
                            bootstrap_at=bootstrap_at,
                        ),
                        "AOI_verified",
                    ),
                    (
                        f"{department}-identity",
                        "department.created",
                        _department_identity(
                            binding,
                            department=department,
                            department_id=department_id,
                            lead_node_id=lead_node_id,
                            bootstrap_at=bootstrap_at,
                        ),
                        "AOI_verified",
                    ),
                    (
                        f"{department}-snapshot-rev1",
                        "department.snapshot.recorded",
                        department_snapshots[department],
                        "AOI_verified",
                    ),
                ),
            )
        payloads.extend(
            (
                (
                    "chief-term",
                    "chief.term.created",
                    {
                        "contract_type": CHIEF_TERM_V1,
                        "schema_version": 1,
                        **binding,
                        "chief_id": ids["chief"],
                        "carrier_id": chief_carrier_id,
                        "term": 1,
                        "epoch": 1,
                        "state": "active",
                        "issued_at": bootstrap_at,
                        "ended_at": None,
                        "previous_transaction_sha256": ZERO_SHA256,
                        "takeover_capability_sha256": None,
                        "takeover_consumption_receipt_sha256": None,
                        "observation": {"state": "known", "reason": "observed"},
                    },
                    "AOI_verified",
                ),
                (
                    "chief-carrier",
                    "carrier.bound",
                    carrier,
                    _carrier_provenance(known_carrier),
                ),
            ),
        )
        if known_carrier is not None:
            payloads.append(
                (
                    "chief-carrier-execution",
                    "execution.created",
                    _chief_execution_node(
                        binding,
                        execution_id=ids["chief_execution"],
                        chief_node_id=chief_node_id,
                        carrier=carrier,
                        thread_id=str(known_carrier["thread_id"]),
                        provenance=_carrier_provenance(known_carrier),
                        bootstrap_at=bootstrap_at,
                    ),
                    _carrier_provenance(known_carrier),
                ),
            )
        transaction_id = ids["transaction"]
        request = build_company_transaction_request(
            heads,
            authority,
            transaction_id=transaction_id,
            command_id=ids["command"],
            events=[
                CompanyEventDraft(
                    event_id=ids[f"{suffix.replace('-', '_')}_event"],
                    event_type=event_type,
                    recorded_at=bootstrap_at,
                    payload=payload,
                    provenance=provenance,
                )
                for suffix, event_type, payload, provenance in payloads
            ],
        )
        self._state.commit(request, recorded_at=bootstrap_at)

    def _validate_genesis(
        self,
        *,
        bootstrap_at: str | None = None,
        grant_expires_at: str | None = None,
        known_carrier: Mapping[str, Any] | None = None,
    ) -> None:
        """Reject a reopened incarnation without the one complete genesis graph."""

        manifest = validate_company_manifest(self._state.resolved.manifest)
        company_id = str(manifest["company_id"])
        incarnation = int(manifest["company_incarnation"])
        generation = int(manifest["lock_domain_generation"])
        binding = {
            "company_id": company_id,
            "company_incarnation": incarnation,
            "lock_domain_generation": generation,
        }
        ids = _genesis_ids(company_id, incarnation, generation)
        records = self._state.records_after(0, limit=2)
        if not records or records[0].global_sequence != 1:
            raise CompanySupervisorError("company ledger lacks a genesis transaction")
        first = records[0]
        expected_suffixes = [
            "manifest", "supervisor-grant", "chief-grant", "chief-node",
            "rtl-lead-node", "rtl-identity", "rtl-snapshot-rev1",
            "dv-lead-node", "dv-identity", "dv-snapshot-rev1",
            "pd-lead-node", "pd-identity", "pd-snapshot-rev1",
            "chief-term", "chief-carrier",
        ]
        immutable_events = {str(item.event["event_id"]): dict(item.event) for item in first.events}
        carrier_event = immutable_events.get(ids["chief_carrier_event"])
        if carrier_event is None:
            raise CompanySupervisorError("company genesis carrier event is missing")
        genesis_carrier = dict(carrier_event["payload"])
        known_genesis = genesis_carrier.get("state") == "active"
        if known_genesis:
            expected_suffixes.append("chief-carrier-execution")
        expected_event_ids = {ids[f"{suffix.replace('-', '_')}_event"] for suffix in expected_suffixes}
        if set(immutable_events) != expected_event_ids or len(first.events) != len(expected_event_ids):
            raise CompanySupervisorError("company genesis event IDs are incomplete")
        genesis_at = str(dict(immutable_events[ids["manifest_event"]]["payload"])["created_at"])
        if any(event["recorded_at"] != genesis_at for event in immutable_events.values()):
            raise CompanySupervisorError("company genesis timestamps are inconsistent")
        if first.request["transaction_id"] != ids["transaction"] or first.request["command_id"] != ids["command"]:
            raise CompanySupervisorError("company genesis transaction identity is invalid")
        expected_event_types = {
            "manifest": "manifest.recorded", "supervisor-grant": "authority.granted",
            "chief-grant": "authority.granted", "chief-node": "organization.created",
            "rtl-lead-node": "organization.created", "dv-lead-node": "organization.created",
            "pd-lead-node": "organization.created", "rtl-identity": "department.created",
            "dv-identity": "department.created", "pd-identity": "department.created",
            "rtl-snapshot-rev1": "department.snapshot.recorded",
            "dv-snapshot-rev1": "department.snapshot.recorded",
            "pd-snapshot-rev1": "department.snapshot.recorded",
            "chief-term": "chief.term.created", "chief-carrier": "carrier.bound",
            "chief-carrier-execution": "execution.created",
        }
        for suffix in expected_suffixes:
            event = immutable_events[ids[f"{suffix.replace('-', '_')}_event"]]
            if event["event_type"] != expected_event_types[suffix] or event["recorded_at"] != genesis_at:
                raise CompanySupervisorError("company genesis event payload is invalid")
            if {key: event["payload"][key] for key in binding} != binding:
                raise CompanySupervisorError("company genesis event binding is invalid")
        expires_at = str(dict(immutable_events[ids["supervisor_grant_event"]]["payload"])["expires_at"])
        expected_grants = {
            ids["supervisor_grant_event"]: _authority_grant(binding, grant_id=ids["supervisor_grant"], actor_id=ids["supervisor"], actor_kind="supervisor", carrier_id=None, chief_epoch=None, permissions=["company.mutate"], bootstrap_at=genesis_at, grant_expires_at=expires_at),
            ids["chief_grant_event"]: _authority_grant(binding, grant_id=ids["chief_grant"], actor_id=ids["chief"], actor_kind="chief", carrier_id=genesis_carrier["carrier_id"], chief_epoch=1, permissions=["company.mutate"], bootstrap_at=genesis_at, grant_expires_at=expires_at),
        }
        actual_grants = {
            event_id: {
                **dict(immutable_events[event_id]["payload"]),
                "permissions": list(immutable_events[event_id]["payload"]["permissions"]),
            }
            for event_id in expected_grants
        }
        if actual_grants != expected_grants:
            raise CompanySupervisorError("company genesis authority payload is invalid")
        if _plain(immutable_events[ids["manifest_event"]]["payload"]) != manifest:
            raise CompanySupervisorError("company genesis manifest payload is invalid")
        expected_nodes = {
            ids["chief_node_event"]: _organization_node(binding, node_id=ids["chief_node"], department_id=None, parent_node_id=None, role="chief", reports_to_node_id=None, delegation_depth=0, bootstrap_at=genesis_at),
        }
        for department in ("rtl", "dv", "pd"):
            department_id = ids[f"{department}_department"]
            lead_id = ids[f"{department}_lead_node"]
            expected_nodes[ids[f"{department}_lead_node_event"]] = _organization_node(binding, node_id=lead_id, department_id=department_id, parent_node_id=ids["chief_node"], role=f"{department}_lead", reports_to_node_id=ids["chief_node"], delegation_depth=1, status="parked", bootstrap_at=genesis_at)
            identity_id = ids[f"{department}_identity_event"]
            snapshot_id = ids[f"{department}_snapshot_rev1_event"]
            if _plain(immutable_events[identity_id]["payload"]) != _department_identity(binding, department=department, department_id=department_id, lead_node_id=lead_id, bootstrap_at=genesis_at) or _plain(immutable_events[snapshot_id]["payload"]) != _department_snapshot(binding, department=department, department_id=department_id, lead_node_id=lead_id, bootstrap_at=genesis_at):
                raise CompanySupervisorError("company genesis department payload is invalid")
        if any(_plain(immutable_events[event_id]["payload"]) != payload for event_id, payload in expected_nodes.items()):
            raise CompanySupervisorError("company genesis organization payload is invalid")
        expected_term = {
            "contract_type": CHIEF_TERM_V1, "schema_version": 1, **binding,
            "chief_id": ids["chief"], "carrier_id": genesis_carrier["carrier_id"], "term": 1,
            "epoch": 1, "state": "active", "issued_at": genesis_at, "ended_at": None,
            "previous_transaction_sha256": ZERO_SHA256, "takeover_capability_sha256": None,
            "takeover_consumption_receipt_sha256": None,
            "observation": {"state": "known", "reason": "observed"},
        }
        if _plain(immutable_events[ids["chief_term_event"]]["payload"]) != expected_term:
            raise CompanySupervisorError("company genesis Chief payload is invalid")
        genesis_execution_event: Mapping[str, Any] | None = None
        if known_genesis:
            genesis_execution_event = immutable_events[ids["chief_carrier_execution_event"]]
            execution = dict(genesis_execution_event["payload"])
            carrier_provenance = str(carrier_event["provenance"])
            observed_carrier = {
                "carrier_id": genesis_carrier.get("carrier_id"),
                "provider": genesis_carrier.get("provider"),
                "model": genesis_carrier.get("model"),
                "session_id": genesis_carrier.get("session_id"),
                "thread_id": execution.get("thread_id"),
                "provenance": carrier_provenance,
                "observation": genesis_carrier.get("observation"),
            }
            try:
                expected_carrier = _carrier_payload(
                    binding,
                    actor_id=ids["chief"],
                    carrier_id=ids["chief_carrier"],
                    bootstrap_at=genesis_at,
                    known_carrier=observed_carrier,
                )
            except CompanySupervisorError as exc:
                raise CompanySupervisorError(
                    "company known genesis carrier payload is invalid",
                ) from exc
            expected_execution = _chief_execution_node(binding, execution_id=ids["chief_execution"], chief_node_id=ids["chief_node"], carrier=expected_carrier, thread_id=str(observed_carrier["thread_id"]), provenance=carrier_provenance, bootstrap_at=genesis_at)
            if _plain(genesis_carrier) != expected_carrier:
                raise CompanySupervisorError(
                    "company genesis carrier payload is invalid",
                )
            if (
                _plain(execution) != expected_execution
                or str(genesis_execution_event["provenance"])
                != carrier_provenance
            ):
                raise CompanySupervisorError("company genesis execution payload is invalid")
        elif (
            _plain(genesis_carrier)
            != _carrier_payload(
                binding,
                actor_id=ids["chief"],
                carrier_id=ids["chief_carrier"],
                bootstrap_at=genesis_at,
                known_carrier=None,
            )
            or str(carrier_event["provenance"]) != "unknown"
        ):
            raise CompanySupervisorError("company genesis carrier payload is invalid")
        if bootstrap_at is not None and bootstrap_at != genesis_at:
            raise CompanySupervisorError("bootstrap retry time differs from durable genesis")
        if grant_expires_at is not None and grant_expires_at != expires_at:
            raise CompanySupervisorError("bootstrap retry expiry differs from durable genesis")
        if bootstrap_at is not None:
            if (known_carrier is not None) != known_genesis:
                raise CompanySupervisorError("carrier mode retry differs from durable genesis")
            if known_carrier is not None:
                expected_retry_carrier = _carrier_payload(binding, actor_id=ids["chief"], carrier_id=ids["chief_carrier"], bootstrap_at=genesis_at, known_carrier=known_carrier)
                expected_retry_execution = _chief_execution_node(binding, execution_id=ids["chief_execution"], chief_node_id=ids["chief_node"], carrier=expected_retry_carrier, thread_id=str(known_carrier["thread_id"]), provenance=_carrier_provenance(known_carrier), bootstrap_at=genesis_at)
                if (
                    _plain(genesis_carrier) != expected_retry_carrier
                    or genesis_execution_event is None
                    or _plain(genesis_execution_event["payload"]) != expected_retry_execution
                    or str(genesis_execution_event["provenance"]) != _carrier_provenance(known_carrier)
                ):
                    raise CompanySupervisorError("known carrier payload retry differs from durable genesis")
        objects = {
            contract_type: [dict(item.payload) for item in self._state.objects(contract_type=contract_type)]
            for contract_type in (
                COMPANY_MANIFEST_V1,
                AUTHORITY_GRANT_V1,
                ORGANIZATION_NODE_V1,
                DEPARTMENT_IDENTITY_V1,
                DEPARTMENT_SNAPSHOT_V1,
                CHIEF_TERM_V1,
                CARRIER_BINDING_V1,
                EXECUTION_NODE_V1,
            )
        }
        if not any(item == manifest for item in objects[COMPANY_MANIFEST_V1]):
            raise CompanySupervisorError("company core manifest is absent")
        grants = {item.get("actor_id"): item for item in objects[AUTHORITY_GRANT_V1]}
        if not {ids["supervisor"], ids["chief"]} <= set(grants):
            raise CompanySupervisorError("company core authority graph is absent")
        nodes = {item.get("node_id"): item for item in objects[ORGANIZATION_NODE_V1]}
        required_nodes = {ids["chief_node"], *(ids[f"{department}_lead_node"] for department in ("rtl", "dv", "pd"))}
        if not required_nodes <= set(nodes):
            raise CompanySupervisorError("company core organization graph is absent")
        departments = {item.get("department_id"): item for item in objects[DEPARTMENT_IDENTITY_V1]}
        required_departments = {ids[f"{department}_department"] for department in ("rtl", "dv", "pd")}
        if not required_departments <= set(departments):
            raise CompanySupervisorError("company core departments are absent")
        snapshots = {item.get("department_id"): item for item in objects[DEPARTMENT_SNAPSHOT_V1]}
        if not required_departments <= set(snapshots):
            raise CompanySupervisorError("company core department snapshots are absent")

    def close(self) -> None:
        server = self._dashboard_server
        self._dashboard_server = None
        self._dashboard_cache = None
        self._dashboard_environment_kind = None
        try:
            if server is not None:
                server.close()
        finally:
            self._state.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _department_lifecycle_ids(
    binding: Mapping[str, Any],
    *,
    operation: str,
    department_id: str,
    transaction_id: str,
    command_id: str,
) -> dict[str, str]:
    digest = company_contract_sha256({
        **dict(binding),
        "operation": operation,
        "department_id": department_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
    })
    return {
        name: f"department-{name}-{digest}"
        for name in (
            "control_intent",
            "control_receipt",
            "snapshot_event",
            "lead_event",
            "identity_event",
            "carrier_event",
            "dispatch_event",
            "intent_event",
            "dispatch_revision",
        )
    }


def _department_scope_sha256(
    department_id: str,
    snapshot: ProjectedObject,
) -> str:
    return company_contract_sha256({
        "department_id": department_id,
        "snapshot_id": snapshot.payload["snapshot_id"],
        "snapshot_payload_sha256":
            company_contract_sha256(_plain(snapshot.payload)),
    })


def _department_lifecycle_request(
    binding: Mapping[str, Any],
    *,
    operation: str,
    trigger: str,
    requested_at: str,
    identity_item: ProjectedObject,
    lead_item: ProjectedObject,
    snapshot_item: ProjectedObject,
    carrier_item: ProjectedObject | None,
    scope_sha256: str,
    heads: LedgerHeadsSnapshot,
    snapshot_document: Mapping[str, Any] | None = None,
    dispatch_request_id: str | None = None,
    reservation_id: str | None = None,
    task_id: str | None = None,
    packet_id: str | None = None,
    route_policy_id: str | None = None,
    requested_role: str | None = None,
    requested_capability_tier: str | None = None,
) -> dict[str, Any]:
    return validate_department_lifecycle_request({
        "request_type": "department_lifecycle_request_v1",
        "schema_version": 1,
        **dict(binding),
        "operation": operation,
        "trigger": trigger,
        "requested_at": requested_at,
        "department_id": identity_item.payload["department_id"],
        "lead_node_id": lead_item.payload["node_id"],
        "expected_global_sequence":
            heads.global_head.global_sequence,
        "expected_transaction_sha256":
            heads.global_head.transaction_sha256,
        "expected_department_status": identity_item.payload["status"],
        "expected_department_payload_sha256":
            company_contract_sha256(_plain(identity_item.payload)),
        "expected_lead_status": lead_item.payload["status"],
        "expected_lead_payload_sha256":
            company_contract_sha256(_plain(lead_item.payload)),
        "expected_snapshot_id": snapshot_item.payload["snapshot_id"],
        "expected_snapshot_revision": snapshot_item.payload["revision"],
        "expected_snapshot_payload_sha256":
            company_contract_sha256(_plain(snapshot_item.payload)),
        "expected_carrier_id":
            None if carrier_item is None
            else carrier_item.payload["carrier_id"],
        "expected_carrier_payload_sha256":
            None if carrier_item is None
            else company_contract_sha256(_plain(carrier_item.payload)),
        "requested_scope_sha256": scope_sha256,
        "dispatch_request_id": dispatch_request_id,
        "reservation_id": reservation_id,
        "task_id": task_id,
        "packet_id": packet_id,
        "route_policy_id": route_policy_id,
        "requested_role": requested_role,
        "requested_capability_tier": requested_capability_tier,
        "snapshot_document":
            None if snapshot_document is None else dict(snapshot_document),
    })


def _department_control_intent(
    binding: Mapping[str, Any],
    *,
    ids: Mapping[str, str],
    command_id: str,
    execution_id: str,
    grant: Mapping[str, Any],
    request: Mapping[str, Any],
    result: Mapping[str, Any],
    transaction_id: str,
    created_at: str,
    terminal_at: str,
) -> dict[str, Any]:
    terminal_receipt = {
        "receipt_type": DEPARTMENT_LIFECYCLE_RECEIPT_V1,
        "schema_version": 1,
        **dict(binding),
        "transaction_id": transaction_id,
        "command_id": command_id,
        "committed_cursor": result["committed_cursor"],
        "operation": result["operation"],
        "department_id": result["department_id"],
    }
    return validate_control_intent({
        "contract_type": CONTROL_INTENT_V1,
        "schema_version": 1,
        **dict(binding),
        "control_intent_id": ids["control_intent"],
        "command_id": command_id,
        "execution_id": execution_id,
        "authority_grant": _plain(grant),
        "authority_grant_sha256": grant["grant_sha256"],
        "request_payload": _plain(request),
        "request_sha256": company_contract_sha256(
            _plain(request),
            max_bytes=64 * 1024,
        ),
        "outcome": "committed",
        "result_payload": _plain(result),
        "result_sha256": company_contract_sha256(
            _plain(result),
            max_bytes=64 * 1024,
        ),
        "receipt_id": ids["control_receipt"],
        "terminal_receipt": terminal_receipt,
        "receipt_sha256": company_contract_sha256(
            terminal_receipt,
            max_bytes=64 * 1024,
        ),
        "created_at": created_at,
        "terminal_at": terminal_at,
        "provenance": "AOI_verified",
        "observation": {"state": "known", "reason": "observed"},
    })


def _department_lifecycle_replay(
    record: LedgerTransactionRecord,
    *,
    operation: str,
    department_id: str,
    command_id: str,
    requested_at: str,
    recorded_at: str,
    trigger: str | None = None,
    snapshot_document_sha256: str | None = None,
    dispatch_request_id: str | None = None,
    reservation_id: str | None = None,
    task_id: str | None = None,
    packet_id: str | None = None,
    route_policy_id: str | None = None,
    requested_role: str | None = None,
    requested_capability_tier: str | None = None,
) -> DepartmentLifecycleResult:
    """Return an exact durable retry or reject every divergent argument."""

    if record.reservations or not record.events:
        raise CompanyDepartmentLifecycleError(
            "durable department lifecycle is not committed",
        )
    transaction_id = str(record.request["transaction_id"])
    durable_command_id = str(record.request["command_id"])
    if (
        durable_command_id != command_id
        or str(record.receipt["state"]) != "committed"
    ):
        raise CompanyDepartmentLifecycleError(
            "department lifecycle retry differs from its durable command",
        )

    wrappers = [_plain(member.event) for member in record.events]
    work_binding_payloads = [
        wrapper["payload"]
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type")
        == WORK_DISPATCH_BINDING_V1
    ]
    if len(work_binding_payloads) > 1:
        raise CompanyDepartmentLifecycleError(
            "durable department lifecycle has ambiguous work bindings",
        )
    intents = [
        wrapper["payload"]
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == CONTROL_INTENT_V1
    ]
    if len(intents) != 1:
        raise CompanyDepartmentLifecycleError(
            "durable department lifecycle lacks one control intent",
        )
    try:
        intent = validate_control_intent(intents[0])
        request = validate_department_lifecycle_request(
            intent["request_payload"],
        )
        result = validate_department_lifecycle_result(
            intent["result_payload"],
            request=request,
        )
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "durable department lifecycle contract is invalid",
        ) from exc
    if (
        request["request_type"] != DEPARTMENT_LIFECYCLE_REQUEST_V1
        or result["result_type"] != DEPARTMENT_LIFECYCLE_RESULT_V1
        or request["operation"] != operation
        or result["operation"] != operation
        or request["department_id"] != department_id
        or result["department_id"] != department_id
        or intent["command_id"] != command_id
        or result["command_id"] != command_id
        or result["transaction_id"] != transaction_id
        or request["requested_at"] != requested_at
        or intent["created_at"] != requested_at
        or intent["terminal_at"] != recorded_at
        or result["committed_cursor"] != record.global_sequence
    ):
        raise CompanyDepartmentLifecycleError(
            "department lifecycle retry differs from durable bytes",
        )

    expected_routing = {
        "dispatch_request_id": dispatch_request_id,
        "reservation_id": reservation_id,
        "task_id": task_id,
        "packet_id": packet_id,
        "route_policy_id": route_policy_id,
        "requested_role": requested_role,
        "requested_capability_tier": requested_capability_tier,
    }
    if any(request[name] != value for name, value in expected_routing.items()):
        raise CompanyDepartmentLifecycleError(
            "department lifecycle retry routing differs",
        )
    if trigger is not None and request["trigger"] != trigger:
        raise CompanyDepartmentLifecycleError(
            "department lifecycle retry trigger differs",
        )
    snapshot_ref = request["snapshot_document"]
    if snapshot_document_sha256 is not None:
        if (
            not isinstance(snapshot_ref, Mapping)
            or snapshot_ref.get("sha256") != snapshot_document_sha256
        ):
            raise CompanyDepartmentLifecycleError(
                "department lifecycle retry snapshot differs",
            )
    elif snapshot_ref is not None:
        raise CompanyDepartmentLifecycleError(
            "department lifecycle retry unexpectedly names a snapshot",
        )

    binding = {
        key: request[key]
        for key in (
            "company_id",
            "company_incarnation",
            "lock_domain_generation",
        )
    }
    ids = _department_lifecycle_ids(
        binding,
        operation=operation,
        department_id=department_id,
        transaction_id=transaction_id,
        command_id=command_id,
    )
    if (
        intent["control_intent_id"] != ids["control_intent"]
        or intent["receipt_id"] != ids["control_receipt"]
    ):
        raise CompanyDepartmentLifecycleError(
            "durable department lifecycle identifiers differ",
        )

    expected: list[tuple[str, str, str, str]] = []
    if operation == "park":
        expected.extend((
            (
                ids["snapshot_event"],
                "org",
                "department.snapshot.recorded",
                DEPARTMENT_SNAPSHOT_V1,
            ),
            (
                ids["lead_event"],
                "org",
                "department.organization.parked",
                ORGANIZATION_NODE_V1,
            ),
            (
                ids["identity_event"],
                "org",
                "department.identity.parked",
                DEPARTMENT_IDENTITY_V1,
            ),
        ))
        if result["carrier_transition"] == "parked":
            expected.append((
                ids["carrier_event"],
                "org",
                "department.carrier.parked",
                CARRIER_BINDING_V1,
            ))
        expected.append((
            ids["intent_event"],
            "execution",
            "department.park.intent.committed",
            CONTROL_INTENT_V1,
        ))
    else:
        if request["expected_department_status"] == "parked":
            expected.extend((
                (
                    ids["lead_event"],
                    "org",
                    "department.organization.activated",
                    ORGANIZATION_NODE_V1,
                ),
                (
                    ids["identity_event"],
                    "org",
                    "department.identity.activated",
                    DEPARTMENT_IDENTITY_V1,
                ),
            ))
        expected.extend((
            (
                ids["dispatch_event"],
                "execution",
                "dispatch.request.queued",
                DISPATCH_REQUEST_V1,
            ),
        ))
        if work_binding_payloads:
            expected.append((
                _work_definition_id(
                    binding,
                    "dispatch-binding-event",
                    transaction_id,
                ),
                "execution",
                "work.dispatch.bound",
                WORK_DISPATCH_BINDING_V1,
            ))
        expected.append((
                ids["intent_event"],
                "execution",
                (
                    "department.resume.intent.committed"
                    if operation == "resume"
                    else "department.dispatch.intent.committed"
                ),
                CONTROL_INTENT_V1,
            ))

    if len(wrappers) != len(expected):
        raise CompanyDepartmentLifecycleError(
            "durable department lifecycle event membership differs",
        )
    for wrapper, (
        event_id,
        stream,
        event_type,
        contract_type,
    ) in zip(wrappers, expected, strict=True):
        if (
            wrapper["event_id"] != event_id
            or wrapper["stream"] != stream
            or wrapper["event_type"] != event_type
            or wrapper["recorded_at"] != recorded_at
            or wrapper["provenance"] != "AOI_verified"
            or wrapper["payload"].get("contract_type") != contract_type
        ):
            raise CompanyDepartmentLifecycleError(
                "durable department lifecycle event envelope differs",
            )

    if dispatch_request_id is not None:
        dispatches = [
            wrapper["payload"]
            for wrapper in wrappers
            if wrapper["payload"].get("contract_type")
            == DISPATCH_REQUEST_V1
        ]
        if len(dispatches) != 1:
            raise CompanyDepartmentLifecycleError(
                "durable department lifecycle dispatch is missing",
            )
        dispatch = validate_dispatch_request(dispatches[0])
        if (
            dispatch["dispatch_request_id"] != dispatch_request_id
            or dispatch["reservation_id"] != reservation_id
            or dispatch["task_id"] != task_id
            or dispatch["packet_id"] != packet_id
            or dispatch["route_policy_id"] != route_policy_id
            or dispatch["requested_role"] != requested_role
            or dispatch["requested_capability_tier"]
            != requested_capability_tier
            or dispatch["department_id"] != department_id
            or dispatch["command_id"] != command_id
            or dispatch["state"] != "queued"
            or dispatch["revision"] != 1
            or dispatch["dispatch_revision_id"]
            != ids["dispatch_revision"]
            or result["dispatch_request_id"] != dispatch_request_id
            or result["dispatch_state"] != "queued"
        ):
            raise CompanyDepartmentLifecycleError(
                "durable department lifecycle dispatch differs",
            )
        if work_binding_payloads:
            try:
                work_binding = validate_work_dispatch_binding(
                    work_binding_payloads[0],
                )
            except ValueError as exc:
                raise CompanyDepartmentLifecycleError(
                    "durable department work binding is invalid",
                ) from exc
            if (
                work_binding["transaction_id"] != transaction_id
                or work_binding["command_id"] != command_id
                or work_binding["dispatch_request_id"]
                != dispatch_request_id
                or work_binding["dispatch_revision_id"]
                != dispatch["dispatch_revision_id"]
                or work_binding["dispatch_payload_sha256"]
                != company_contract_sha256(dispatch)
                or tuple(
                    work_binding[name]
                    for name in (
                        "task_id",
                        "packet_id",
                        "department_id",
                        "target_node_id",
                        "manager_node_id",
                        "parent_execution_id",
                        "delegation_depth",
                    )
                )
                != tuple(
                    dispatch[name]
                    for name in (
                        "task_id",
                        "packet_id",
                        "department_id",
                        "target_node_id",
                        "manager_node_id",
                        "parent_execution_id",
                        "delegation_depth",
                    )
                )
            ):
                raise CompanyDepartmentLifecycleError(
                    "durable department work binding differs",
                )

    return _department_lifecycle_result_from_record(
        record,
        result,
        idempotent_replay=True,
    )


def _require_durable_department_dispatch_chief_fence(
    record: LedgerTransactionRecord,
    *,
    chief_id: str,
    carrier_id: str,
    term: int,
    epoch: int,
    chief_execution_id: str,
) -> None:
    """Bind an enqueue replay to its original authorizing Chief tuple."""

    if record.reservations or not record.events:
        raise CompanyDepartmentLifecycleError(
            "durable department dispatch is not committed",
        )
    intents = [
        _plain(member.event["payload"])
        for member in record.events
        if (
            member.event["payload"].get("contract_type")
            == CONTROL_INTENT_V1
        )
    ]
    if len(intents) != 1:
        raise CompanyDepartmentLifecycleError(
            "durable department dispatch lacks one control intent",
        )
    try:
        intent = validate_control_intent(intents[0])
        grant = validate_authority_grant(intent["authority_grant"])
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "durable department dispatch Chief authority is invalid",
        ) from exc
    if (
        grant["actor_kind"] != "chief"
        or grant["actor_id"] != chief_id
        or grant["carrier_id"] != carrier_id
        or grant["term"] != term
        or grant["chief_epoch"] != epoch
        or intent["execution_id"] != chief_execution_id
    ):
        raise CompanyDepartmentLifecycleError(
            "department dispatch replay Chief fence differs",
        )


def _department_lifecycle_replay_times(
    record: LedgerTransactionRecord,
) -> tuple[str, str]:
    """Recover server-owned timestamps before exact lifecycle replay checks."""

    wrappers = [_plain(member.event) for member in record.events]
    intents = [
        wrapper["payload"]
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == CONTROL_INTENT_V1
    ]
    if len(intents) != 1:
        raise CompanyDepartmentLifecycleError(
            "durable department lifecycle lacks one control intent",
        )
    try:
        intent = validate_control_intent(intents[0])
        request = validate_department_lifecycle_request(
            intent["request_payload"],
        )
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "durable department lifecycle contract is invalid",
        ) from exc
    return str(request["requested_at"]), str(intent["terminal_at"])


def _department_lifecycle_result(
    committed: LedgerAppendResult,
    result: Mapping[str, Any],
) -> DepartmentLifecycleResult:
    return _department_lifecycle_result_from_record(
        committed.record,
        result,
        idempotent_replay=committed.idempotent_replay,
    )


def _department_lifecycle_result_from_record(
    record: LedgerTransactionRecord,
    result: Mapping[str, Any],
    *,
    idempotent_replay: bool,
) -> DepartmentLifecycleResult:
    return DepartmentLifecycleResult(
        operation=str(result["operation"]),
        department_id=str(result["department_id"]),
        lifecycle_state=str(result["lifecycle_state"]),
        snapshot_id=str(result["snapshot_id"]),
        snapshot_revision=int(result["snapshot_revision"]),
        dispatch_request_id=(
            None
            if result["dispatch_request_id"] is None
            else str(result["dispatch_request_id"])
        ),
        dispatch_state=(
            None
            if result["dispatch_state"] is None
            else str(result["dispatch_state"])
        ),
        transaction_id=str(record.request["transaction_id"]),
        command_id=str(record.request["command_id"]),
        global_sequence=record.global_sequence,
        idempotent_replay=idempotent_replay,
    )


def _department_dispatch_revision_id(
    payload: Mapping[str, Any],
    *,
    target_state: str,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "company_id": payload["company_id"],
        "company_incarnation": payload["company_incarnation"],
        "lock_domain_generation": payload["lock_domain_generation"],
        "dispatch_request_id": payload["dispatch_request_id"],
        "previous_revision": payload["revision"],
        "target_state": target_state,
        "transaction_id": transaction_id,
        "command_id": command_id,
    })
    return f"department-dispatch-revision-{digest}"


def _department_dispatch_event_id(
    payload: Mapping[str, Any],
    *,
    transaction_id: str,
) -> str:
    digest = company_contract_sha256({
        "dispatch_revision_id": payload["dispatch_revision_id"],
        "transaction_id": transaction_id,
    })
    return f"department-dispatch-event-{digest}"


def _next_department_dispatch_payload(
    current: ProjectedObject,
    *,
    target_state: str,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
    effect_evidence: Sequence[Mapping[str, Any]],
    reconcile_ref: str | None,
    provenance: str,
    observation: Mapping[str, Any],
    provider_dispatch_id: str | None = None,
    execution_id: str | None = None,
    resolves_event_ids: Sequence[str] = (),
) -> dict[str, Any]:
    old = _plain(current.payload)
    candidate = {
        **old,
        "dispatch_revision_id": _department_dispatch_revision_id(
            old,
            target_state=target_state,
            transaction_id=transaction_id,
            command_id=command_id,
        ),
        "revision": int(old["revision"]) + 1,
        "previous_event_id": current.event_id,
        "previous_payload_sha256": company_contract_sha256(old),
        "command_id": command_id,
        "state": target_state,
        "attempt": 0 if target_state == "admitted" else 1,
        "provider_dispatch_id": provider_dispatch_id,
        "execution_id": execution_id,
        "effect_evidence": [_plain(item) for item in effect_evidence],
        "reconcile_ref": reconcile_ref,
        "resolves_event_ids": list(resolves_event_ids),
        "updated_at": recorded_at,
        "provenance": provenance,
        "observation": _plain(observation),
    }
    try:
        return validate_dispatch_request(candidate)
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "automatic department dispatch revision is invalid",
        ) from exc


def _department_dispatch_replay(
    record: LedgerTransactionRecord,
    *,
    dispatch_request_id: str,
    target_state: str,
    command_id: str,
    recorded_at: str,
    effect_evidence: Sequence[Mapping[str, Any]],
    reconcile_ref: str | None,
    provenance: str,
    observation: Mapping[str, Any],
    receipt_state: str,
    provider_receipt: Mapping[str, Any] | None,
) -> DepartmentDispatchResult:
    members = (
        record.events
        if str(record.receipt["state"]) == "committed"
        else record.reservations
    )
    wrappers = [_plain(member.event) for member in members]
    dispatches = [
        wrapper["payload"]
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == DISPATCH_REQUEST_V1
    ]
    receipts = [
        wrapper["payload"]
        for wrapper in wrappers
        if (
            wrapper["payload"].get("contract_type")
            == PROVIDER_LIFECYCLE_RECEIPT_V1
        )
    ]
    evidence = [
        wrapper["payload"]
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == EVIDENCE_RECORD_V1
    ]
    expected_count = 3 if provider_receipt is not None else 1
    if (
        len(wrappers) != expected_count
        or len(dispatches) != 1
        or str(record.request["command_id"]) != command_id
        or str(record.receipt["state"]) != receipt_state
    ):
        raise CompanyDepartmentLifecycleError(
            "department dispatch retry differs from its durable command",
        )
    try:
        dispatch = validate_dispatch_request(dispatches[0])
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "durable department dispatch contract is invalid",
        ) from exc
    wrapper = wrappers[-1]
    if provider_receipt is None:
        if receipts or evidence:
            raise CompanyDepartmentLifecycleError(
                "local dispatch retry contains provider evidence",
            )
    else:
        expected_receipt = validate_provider_lifecycle_receipt(
            provider_receipt,
        )
        expected_evidence = _provider_lifecycle_evidence(expected_receipt)
        if (
            len(receipts) != 1
            or len(evidence) != 1
            or validate_provider_lifecycle_receipt(receipts[0])
            != expected_receipt
            or validate_evidence_record(evidence[0]) != expected_evidence
            or [item["event_type"] for item in wrappers[:2]]
            != [
                f"provider.lifecycle.{expected_receipt['event_kind']}",
                "evidence.provider_lifecycle.observed",
            ]
        ):
            raise CompanyDepartmentLifecycleError(
                "terminal dispatch retry provider evidence differs",
            )
    if (
        dispatch["dispatch_request_id"] != dispatch_request_id
        or dispatch["state"] != target_state
        or dispatch["command_id"] != command_id
        or dispatch["effect_evidence"]
        != [_plain(item) for item in effect_evidence]
        or dispatch["reconcile_ref"] != reconcile_ref
        or dispatch["provenance"] != provenance
        or dispatch["observation"] != _plain(observation)
        or wrapper["event_id"]
        != _department_dispatch_event_id(
            dispatch,
            transaction_id=str(record.request["transaction_id"]),
        )
        or wrapper["stream"] != "execution"
        or wrapper["event_type"] != f"dispatch.request.{target_state}"
        or wrapper["recorded_at"] != recorded_at
        or wrapper["provenance"] != provenance
    ):
        raise CompanyDepartmentLifecycleError(
            "department dispatch retry differs from durable bytes",
        )
    return _department_dispatch_result(
        record,
        dispatch,
        idempotent_replay=True,
    )


def _department_dispatch_replay_time(record: LedgerTransactionRecord) -> str:
    """Recover the one server stamp for an exact admission retry."""

    wrappers = [_plain(member.event) for member in record.events]
    dispatches = [
        wrapper
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == DISPATCH_REQUEST_V1
    ]
    if len(dispatches) != 1 or type(dispatches[0].get("recorded_at")) is not str:
        raise CompanyDepartmentLifecycleError(
            "durable department dispatch lacks one recorded timestamp",
        )
    return str(dispatches[0]["recorded_at"])


def _department_dispatch_result(
    record: LedgerTransactionRecord,
    dispatch: Mapping[str, Any],
    *,
    idempotent_replay: bool,
) -> DepartmentDispatchResult:
    members = record.events if record.events else record.reservations
    carrier_ids = {
        str(member.event["payload"]["carrier_id"])
        for member in members
        if (
            member.event["payload"].get("contract_type")
            == CARRIER_BINDING_V1
            and member.event["payload"].get("state") == "active"
        )
    }
    return DepartmentDispatchResult(
        dispatch_request_id=str(dispatch["dispatch_request_id"]),
        dispatch_state=str(dispatch["state"]),
        revision=int(dispatch["revision"]),
        transaction_id=str(record.request["transaction_id"]),
        command_id=str(record.request["command_id"]),
        receipt_state=str(record.receipt["state"]),
        global_sequence=record.global_sequence,
        execution_id=(
            None
            if dispatch["execution_id"] is None
            else str(dispatch["execution_id"])
        ),
        carrier_id=(
            next(iter(carrier_ids))
            if len(carrier_ids) == 1
            else None
        ),
        idempotent_replay=idempotent_replay,
    )


def _provider_lifecycle_evidence(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = {
        "contract_type": EVIDENCE_RECORD_V1,
        "schema_version": 1,
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "evidence_id": (
            f"provider-lifecycle-evidence-{receipt['receipt_sha256']}"
        ),
        "execution_id": receipt["execution_id"],
        "claim_id": receipt["receipt_id"],
        "evidence_class": "runtime",
        "status": "observed",
        "artifact": _plain(receipt["raw_artifact"]),
        "command_sha256": None,
        "verification_sha256": receipt["receipt_sha256"],
        "recorded_at": receipt["observed_at"],
        "provenance": receipt["provenance"],
        "observation": _plain(receipt["observation"]),
    }
    try:
        return validate_evidence_record(candidate)
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "provider lifecycle evidence record is invalid",
        ) from exc


def _runtime_observation_evidence(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Project a receipt-bound runtime observation as evidence, not completion."""

    candidate = {
        "contract_type": EVIDENCE_RECORD_V1,
        "schema_version": 1,
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "evidence_id": (
            f"runtime-observation-evidence-{receipt['receipt_sha256']}"
        ),
        "execution_id": receipt["execution_id"],
        "claim_id": receipt["receipt_id"],
        "evidence_class": "runtime",
        "status": "observed",
        "artifact": _plain(receipt["raw_artifact"]),
        "command_sha256": None,
        "verification_sha256": receipt["receipt_sha256"],
        "recorded_at": receipt["observed_at"],
        "provenance": receipt["provenance"],
        "observation": _plain(receipt["observation"]),
    }
    try:
        return validate_evidence_record(candidate)
    except ValueError as exc:
        raise CompanyExecutionRegistrationError(
            "runtime observation evidence record is invalid",
        ) from exc


def _runtime_observation_alert(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Create the persistent critical alert required by confirmed loss."""

    candidate = {
        "contract_type": ALERT_V1,
        "schema_version": 1,
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "alert_id": f"confirmed-lost-alert-{receipt['receipt_sha256']}",
        "execution_id": receipt["execution_id"],
        "severity": "critical",
        "state": "open",
        "category": "confirmed_lost",
        "created_at": receipt["observed_at"],
        "resolved_at": None,
        "detail_sha256": receipt["receipt_sha256"],
        "observation": _plain(receipt["observation"]),
    }
    try:
        return validate_alert(candidate)
    except ValueError as exc:
        raise CompanyExecutionRegistrationError(
            "runtime observation alert is invalid",
        ) from exc


def _runtime_observation_replay(
    record: LedgerTransactionRecord,
    *,
    execution_id: str,
    receipt: Mapping[str, Any],
    source_bytes: bytes,
    command_id: str,
    recorded_at: str,
) -> ExecutionRuntimeStatusResult:
    """Return only an exact durable runtime-observation replay."""

    if (
        record.request["command_id"] != command_id
        or hashlib.sha256(source_bytes).hexdigest()
        != receipt["raw_artifact"]["sha256"]
        or len(source_bytes) != receipt["raw_artifact"]["size_bytes"]
    ):
        raise CompanyExecutionRegistrationError(
            "runtime observation replay differs from durable command",
        )
    receipts = [
        item.event["payload"] for item in record.events
        if item.event["payload"].get("contract_type")
        == EXECUTION_RUNTIME_OBSERVATION_RECEIPT_V1
    ]
    if len(receipts) != 1 or _plain(receipts[0]) != _plain(receipt):
        raise CompanyExecutionRegistrationError(
            "runtime observation replay receipt differs from durable record",
        )
    executions = [
        item.event["payload"] for item in record.events
        if item.event["payload"].get("contract_type") == EXECUTION_NODE_V1
        and item.event["payload"].get("execution_id") == execution_id
    ]
    expected_status = {
        "telemetry_silent": "telemetry_silent",
        "recovered": "running",
        "confirmed_lost": "confirmed_lost",
    }[str(receipt["transition"])]
    evidence = _runtime_observation_evidence(receipt)
    if (
        len(executions) != 1
        or executions[0].get("runtime_status") != expected_status
        or evidence["evidence_id"] not in executions[0].get("evidence_ids", ())
        or executions[0].get("updated_at") != recorded_at
    ):
        raise CompanyExecutionRegistrationError(
            "runtime observation replay execution differs from durable record",
        )
    evidence_items = [
        item.event["payload"] for item in record.events
        if item.event["payload"].get("contract_type") == EVIDENCE_RECORD_V1
        and item.event["payload"].get("evidence_id") == evidence["evidence_id"]
    ]
    if len(evidence_items) != 1 or _plain(evidence_items[0]) != evidence:
        raise CompanyExecutionRegistrationError(
            "runtime observation replay evidence differs from durable record",
        )
    alert_items = [
        item.event["payload"] for item in record.events
        if item.event["payload"].get("contract_type") == ALERT_V1
    ]
    if receipt["transition"] == "confirmed_lost":
        expected_alert = _runtime_observation_alert(receipt)
        if (
            len(alert_items) != 1
            or _plain(alert_items[0]) != expected_alert
        ):
            raise CompanyExecutionRegistrationError(
                "runtime observation replay alert differs from durable record",
            )
    elif alert_items:
        raise CompanyExecutionRegistrationError(
            "non-loss runtime observation replay contains an alert",
        )
    return _department_execution_status_result(
        record,
        executions[0],
        idempotent_replay=True,
    )


def _provider_lifecycle_drafts(
    receipt: Mapping[str, Any],
    *,
    evidence: Mapping[str, Any] | None = None,
) -> tuple[CompanyEventDraft, CompanyEventDraft]:
    evidence_payload = (
        _provider_lifecycle_evidence(receipt)
        if evidence is None
        else validate_evidence_record(evidence)
    )
    provenance = str(receipt["provenance"])
    recorded_at = str(receipt["observed_at"])
    receipt_event_digest = company_contract_sha256({
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "receipt_id": receipt["receipt_id"],
    })
    source_event_digest = company_contract_sha256({
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "source_event_id": receipt["source_event_id"],
    })
    return (
        CompanyEventDraft(
            event_id=f"provider-lifecycle-receipt-{receipt_event_digest}",
            event_type=f"provider.lifecycle.{receipt['event_kind']}",
            recorded_at=recorded_at,
            payload=receipt,
            provenance=provenance,
        ),
        CompanyEventDraft(
            event_id=f"provider-lifecycle-evidence-{source_event_digest}",
            event_type="evidence.provider_lifecycle.observed",
            recorded_at=recorded_at,
            payload=evidence_payload,
            provenance=provenance,
        ),
    )


def _known_carrier_from_provider_receipt(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "carrier_id": receipt["carrier_id"],
        "provider": receipt["provider"],
        "model": receipt["model"],
        "effort": receipt["effort"],
        "session_id": receipt["session_id"],
        "thread_id": receipt["thread_id"],
        "provenance": receipt["provenance"],
        "observation": _plain(receipt["observation"]),
    }


def _department_known_carrier(
    binding: Mapping[str, Any],
    *,
    lead_node_id: str,
    known_carrier: Mapping[str, Any],
    recorded_at: str,
) -> tuple[dict[str, Any], str, str, str | None]:
    required = {
        "carrier_id",
        "provider",
        "model",
        "session_id",
        "thread_id",
        "provenance",
        "observation",
    }
    if not required <= set(known_carrier) or (
        set(known_carrier) - required - {"effort"}
    ):
        raise CompanyDepartmentLifecycleError(
            "provider carrier observation is incomplete",
        )
    provenance = known_carrier["provenance"]
    if provenance not in _PROVIDER_GRADE_PROVENANCE:
        raise CompanyDepartmentLifecycleError(
            "provider carrier observation is not provider grade",
        )
    observation = known_carrier["observation"]
    if (
        not isinstance(observation, Mapping)
        or observation.get("state") != "known"
    ):
        raise CompanyDepartmentLifecycleError(
            "provider carrier observation is not known",
        )
    thread_id = known_carrier["thread_id"]
    if not isinstance(thread_id, str) or not thread_id:
        raise CompanyDepartmentLifecycleError(
            "provider carrier observation lacks a thread ID",
        )
    effort = known_carrier.get("effort")
    if effort is not None and (not isinstance(effort, str) or not effort):
        raise CompanyDepartmentLifecycleError(
            "provider carrier effort is invalid",
        )
    try:
        carrier = validate_carrier_binding({
            "contract_type": CARRIER_BINDING_V1,
            "schema_version": 1,
            **dict(binding),
            "carrier_id": known_carrier["carrier_id"],
            "actor_id": lead_node_id,
            "provider": known_carrier["provider"],
            "model": known_carrier["model"],
            "session_id": known_carrier["session_id"],
            "session_availability": "available",
            "state": "active",
            "bound_at": recorded_at,
            "last_observed_at": recorded_at,
            "observation": _plain(observation),
        })
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "provider carrier observation is invalid",
        ) from exc
    return carrier, str(provenance), thread_id, effort


def _department_dispatch_execution_id(
    dispatch: Mapping[str, Any],
    *,
    transaction_id: str,
    carrier_id: str,
) -> str:
    digest = company_contract_sha256({
        "dispatch_request_id": dispatch["dispatch_request_id"],
        "transaction_id": transaction_id,
        "carrier_id": carrier_id,
    })
    return f"department-lead-execution-{digest}"


def _department_lead_execution(
    binding: Mapping[str, Any],
    *,
    dispatch: Mapping[str, Any],
    parent: Mapping[str, Any],
    lead: Mapping[str, Any],
    carrier: Mapping[str, Any],
    thread_id: str,
    effort: str | None,
    execution_id: str,
    receipt_id: str,
    evidence_ids: Sequence[str],
    provenance: str,
    recorded_at: str,
) -> dict[str, Any]:
    parent_path = list(parent["execution_path"])
    digest = company_contract_sha256({
        "execution_id": execution_id,
        "dispatch_request_id": dispatch["dispatch_request_id"],
    })
    candidate = {
        "contract_type": EXECUTION_NODE_V1,
        "schema_version": 1,
        **dict(binding),
        "execution_id": execution_id,
        "execution_kind": "agent",
        "display_name": f"{lead['role']} carrier",
        "organization_node_id": lead["node_id"],
        "department_id": dispatch["department_id"],
        "parent_execution_id": parent["execution_id"],
        "execution_depth": int(parent["execution_depth"]) + 1,
        "execution_path": [*parent_path, execution_id],
        "task_id": dispatch["task_id"],
        "packet_id": dispatch["packet_id"],
        "thread_id": thread_id,
        "turn_id": None,
        "agent_id": f"department-agent-{digest}",
        "job_id": None,
        "dispatch_id": dispatch["dispatch_request_id"],
        "registration_id": None,
        "receipt_id": receipt_id,
        "provider": carrier["provider"],
        "model": carrier["model"],
        "effort": effort,
        "carrier_id": carrier["carrier_id"],
        "role": dispatch["requested_role"],
        "delegation_depth": dispatch["delegation_depth"],
        "engineering_status": "active",
        "runtime_status": "running",
        "attention_overlays": [],
        "objective": (
            f"Execute department dispatch {dispatch['dispatch_request_id']}"
        ),
        "phase": "department_dispatch",
        "created_at": recorded_at,
        "updated_at": recorded_at,
        "last_event_at": recorded_at,
        "heartbeat_at": recorded_at,
        "wait_reason": None,
        "current_tool": None,
        "terminal_at": None,
        "usage_cursor": 0,
        "job_ids": [],
        "evidence_ids": list(evidence_ids),
        "provenance": provenance,
        "observation": {"state": "known", "reason": "observed"},
    }
    try:
        return validate_execution_node(candidate)
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "department lead execution is invalid",
        ) from exc


def _department_dispatch_success_replay(
    record: LedgerTransactionRecord,
    *,
    dispatch_request_id: str,
    provider_receipt: Mapping[str, Any],
    command_id: str,
    recorded_at: str,
) -> DepartmentDispatchResult:
    if (
        record.reservations
        or str(record.receipt["state"]) != "committed"
        or str(record.request["command_id"]) != command_id
    ):
        raise CompanyDepartmentLifecycleError(
            "known dispatch retry differs from its durable command",
        )
    wrappers = [_plain(member.event) for member in record.events]
    dispatches = [
        wrapper["payload"]
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == DISPATCH_REQUEST_V1
    ]
    executions = [
        wrapper["payload"]
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == EXECUTION_NODE_V1
    ]
    active_carriers = [
        wrapper["payload"]
        for wrapper in wrappers
        if (
            wrapper["payload"].get("contract_type") == CARRIER_BINDING_V1
            and wrapper["payload"].get("state") == "active"
        )
    ]
    receipts = [
        wrapper["payload"]
        for wrapper in wrappers
        if (
            wrapper["payload"].get("contract_type")
            == PROVIDER_LIFECYCLE_RECEIPT_V1
        )
    ]
    evidence = [
        wrapper["payload"]
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == EVIDENCE_RECORD_V1
    ]
    if (
        len(dispatches) != 1
        or len(executions) != 1
        or len(active_carriers) != 1
        or len(receipts) != 1
        or len(evidence) != 1
        or len(wrappers) not in {5, 6}
    ):
        raise CompanyDepartmentLifecycleError(
            "durable known dispatch lifecycle is incomplete",
        )
    dispatch = validate_dispatch_request(dispatches[0])
    execution = validate_execution_node(executions[0])
    carrier = validate_carrier_binding(active_carriers[0])
    receipt = validate_provider_lifecycle_receipt(receipts[0])
    expected_receipt = validate_provider_lifecycle_receipt(provider_receipt)
    evidence_record = validate_evidence_record(evidence[0])
    if (
        receipt != expected_receipt
        or evidence_record != _provider_lifecycle_evidence(receipt)
        or dispatch["dispatch_request_id"] != dispatch_request_id
        or dispatch["state"] != "dispatched"
        or dispatch["command_id"] != command_id
        or dispatch["provider_dispatch_id"] != receipt["provider_dispatch_id"]
        or dispatch["effect_evidence"] != [receipt["raw_artifact"]]
        or dispatch["execution_id"] != execution["execution_id"]
        or execution["dispatch_id"] != dispatch_request_id
        or carrier["actor_id"] != execution["organization_node_id"]
        or receipt["carrier_id"] != carrier["carrier_id"]
        or receipt["provider"] != carrier["provider"]
        or receipt["model"] != carrier["model"]
        or receipt["session_id"] != carrier["session_id"]
        or receipt["thread_id"] != execution["thread_id"]
        or receipt["effort"] != execution["effort"]
        or execution["receipt_id"] != receipt["receipt_id"]
        or execution["evidence_ids"] != [evidence_record["evidence_id"]]
        or any(wrapper["recorded_at"] != recorded_at for wrapper in wrappers)
    ):
        raise CompanyDepartmentLifecycleError(
            "known dispatch retry differs from durable bytes",
        )
    event_types = [str(wrapper["event_type"]) for wrapper in wrappers]
    if event_types[:2] != [
        "provider.lifecycle.dispatch_succeeded",
        "evidence.provider_lifecycle.observed",
    ] or event_types[-3:] not in (
        [
            "department.carrier.bound",
            "execution.department_lead.created",
            "dispatch.request.dispatched",
        ],
        [
            "department.carrier.resumed",
            "execution.department_lead.created",
            "dispatch.request.dispatched",
        ],
    ) or (
        len(event_types) == 6
        and event_types[2] != "department.carrier.fenced"
    ):
        raise CompanyDepartmentLifecycleError(
            "known dispatch retry event matrix differs",
        )
    return _department_dispatch_result(
        record,
        dispatch,
        idempotent_replay=True,
    )


def _department_execution_stop_event_id(
    execution_id: str,
    *,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "execution_id": execution_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "transition": "runtime_stopped",
    })
    return f"department-execution-stop-{digest}"


def _department_execution_stop_replay(
    record: LedgerTransactionRecord,
    *,
    execution_id: str,
    command_id: str,
    provider_receipt: Mapping[str, Any],
    recorded_at: str,
) -> ExecutionRuntimeStatusResult:
    wrappers = [_plain(member.event) for member in record.events]
    if (
        record.reservations
        or str(record.receipt["state"]) != "committed"
        or str(record.request["command_id"]) != command_id
        or len(wrappers) != 3
    ):
        raise CompanyDepartmentLifecycleError(
            "department execution stop retry differs from its durable command",
        )
    receipt = validate_provider_lifecycle_receipt(wrappers[0]["payload"])
    expected_receipt = validate_provider_lifecycle_receipt(provider_receipt)
    evidence = validate_evidence_record(wrappers[1]["payload"])
    wrapper = wrappers[2]
    try:
        execution = validate_execution_node(wrapper["payload"])
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "durable department execution stop is invalid",
        ) from exc
    if (
        execution["execution_id"] != execution_id
        or receipt != expected_receipt
        or receipt["event_kind"] != "execution_stopped"
        or evidence != _provider_lifecycle_evidence(receipt)
        or execution["engineering_status"] in {"completed", "cancelled"}
        or execution["runtime_status"] != "stopped"
        or execution["receipt_id"] != receipt["receipt_id"]
        or not execution["evidence_ids"]
        or execution["evidence_ids"][-1] != evidence["evidence_id"]
        or execution["provenance"] != receipt["provenance"]
        or execution["observation"] != receipt["observation"]
        or execution["updated_at"] != recorded_at
        or execution["last_event_at"] != recorded_at
        or wrapper["event_id"]
        != _department_execution_stop_event_id(
            execution_id,
            transaction_id=str(record.request["transaction_id"]),
            command_id=command_id,
        )
        or wrapper["stream"] != "execution"
        or wrapper["event_type"] != "execution.department_lead.stopped"
        or wrapper["recorded_at"] != recorded_at
        or wrapper["provenance"] != receipt["provenance"]
        or [item["event_type"] for item in wrappers[:2]]
        != [
            "provider.lifecycle.execution_stopped",
            "evidence.provider_lifecycle.observed",
        ]
    ):
        raise CompanyDepartmentLifecycleError(
            "department execution stop retry differs from durable bytes",
        )
    return _department_execution_status_result(
        record,
        execution,
        idempotent_replay=True,
    )


def _engineering_disposition_evidence(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    evidence = {
        "contract_type": EVIDENCE_RECORD_V1,
        "schema_version": 1,
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "evidence_id": (
            f"engineering-disposition-evidence-{receipt['receipt_sha256']}"
        ),
        "execution_id": receipt["execution_id"],
        "claim_id": receipt["receipt_id"],
        "evidence_class": "engineering_inference",
        "status": "observed",
        "artifact": _plain(receipt["raw_artifact"]),
        "command_sha256": None,
        "verification_sha256": receipt["receipt_sha256"],
        "recorded_at": receipt["observed_at"],
        "provenance": receipt["provenance"],
        "observation": _plain(receipt["observation"]),
    }
    try:
        return validate_evidence_record(evidence)
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "engineering disposition evidence is invalid",
        ) from exc


def _engineering_disposition_receipt_draft(
    receipt: Mapping[str, Any],
) -> CompanyEventDraft:
    return CompanyEventDraft(
        event_id=(
            "engineering-disposition-receipt-"
            f"{receipt['receipt_sha256']}"
        ),
        event_type="engineering_disposition.agent_reported",
        recorded_at=str(receipt["observed_at"]),
        payload=receipt,
        provenance=str(receipt["provenance"]),
    )


def _department_execution_idle_event_id(
    execution_id: str,
    *,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "execution_id": execution_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "transition": "engineering_idle",
    })
    return f"department-execution-idle-{digest}"


def _provider_turn_idle_evidence(
    receipt: Mapping[str, Any],
    *,
    execution_id: str,
    recorded_at: str,
) -> dict[str, Any]:
    evidence = {
        "contract_type": EVIDENCE_RECORD_V1,
        "schema_version": 1,
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "evidence_id": f"provider-turn-idle-evidence-{receipt['receipt_sha256']}",
        "execution_id": execution_id,
        "claim_id": receipt["result_receipt_id"],
        "evidence_class": "engineering_inference",
        "status": "observed",
        "artifact": _plain(receipt["result_ref"]),
        "command_sha256": None,
        "verification_sha256": receipt["receipt_sha256"],
        "recorded_at": recorded_at,
        "provenance": "AOI_verified",
        "observation": {"state": "known", "reason": "observed"},
    }
    try:
        return validate_evidence_record(evidence)
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "provider turn idle evidence is invalid",
        ) from exc


def _provider_turn_idle_event_id(
    execution_id: str,
    *,
    result_receipt_id: str,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "execution_id": execution_id,
        "result_receipt_id": result_receipt_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "transition": "provider_turn_engineering_idle",
    })
    return f"provider-turn-engineering-idle-{digest}"


def _provider_turn_idle_replay(
    record: LedgerTransactionRecord,
    *,
    execution_id: str,
    result_receipt_id: str,
    command_id: str,
    recorded_at: str,
    state_owner: CompanyStateOwner,
) -> ExecutionRuntimeStatusResult:
    wrappers = [_plain(member.event) for member in record.events]
    receipts = [
        validate_provider_turn_result_receipt(_plain(item.payload))
        for item in state_owner.objects(contract_type=PROVIDER_TURN_RESULT_RECEIPT_V1)
        if item.payload["result_receipt_id"] == result_receipt_id
    ]
    if len(receipts) != 1:
        raise CompanyDepartmentLifecycleError(
            "provider turn retry result receipt is missing or ambiguous",
        )
    receipt = receipts[0]
    evidence = _provider_turn_idle_evidence(
        receipt,
        execution_id=execution_id,
        recorded_at=recorded_at,
    )
    try:
        execution = validate_execution_node(wrappers[1]["payload"])
    except (IndexError, KeyError, ValueError) as exc:
        raise CompanyDepartmentLifecycleError(
            "provider turn retry execution is invalid",
        ) from exc
    if (
        record.reservations
        or str(record.receipt["state"]) != "committed"
        or str(record.request["command_id"]) != command_id
        or len(wrappers) != 2
        or validate_evidence_record(wrappers[0]["payload"]) != evidence
        or execution["execution_id"] != execution_id
        or execution["engineering_status"] != "idle"
        or execution["runtime_status"] != "stopped"
        or execution["wait_reason"] != "park_ready"
        or execution["current_tool"] is not None
        or execution["provenance"] != "AOI_verified"
        or execution["observation"] != {"state": "known", "reason": "observed"}
        or not execution["evidence_ids"]
        or execution["evidence_ids"][-1] != evidence["evidence_id"]
        or execution["updated_at"] != recorded_at
        or execution["last_event_at"] != recorded_at
        or wrappers[0]["event_id"] != evidence["evidence_id"]
        or wrappers[0]["stream"] != "evidence"
        or wrappers[0]["event_type"] != "evidence.provider_turn.idle.observed"
        or wrappers[0]["recorded_at"] != recorded_at
        or wrappers[0]["provenance"] != "AOI_verified"
        or wrappers[1]["event_id"] != _provider_turn_idle_event_id(
            execution_id,
            result_receipt_id=result_receipt_id,
            transaction_id=str(record.request["transaction_id"]),
            command_id=command_id,
        )
        or wrappers[1]["stream"] != "execution"
        or wrappers[1]["event_type"] != "execution.provider_turn.idle"
        or wrappers[1]["recorded_at"] != recorded_at
        or wrappers[1]["provenance"] != "AOI_verified"
    ):
        raise CompanyDepartmentLifecycleError(
            "provider turn idle retry differs from durable bytes",
        )
    try:
        raw = state_owner.blobs.read(str(receipt["result_ref"]["sha256"]))
        document = validate_provider_turn_result(json.loads(raw.decode("utf-8")))
    except (BlobStoreError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CompanyDepartmentLifecycleError(
            "provider turn retry result CAS is unavailable or invalid",
        ) from exc
    if (
        canonical_provider_turn_result_bytes(document) != raw
        or hashlib.sha256(raw).hexdigest()
        != receipt["result_ref"]["sha256"]
        or len(raw) != receipt["result_ref"]["size_bytes"]
    ):
        raise CompanyDepartmentLifecycleError(
            "provider turn retry result CAS is not canonical",
        )
    projected = {
        contract_type: tuple(state_owner.objects(contract_type=contract_type))
        for contract_type in (
            PROVIDER_WORKER_IO_RECEIPT_V1,
            PROVIDER_WORKER_OPERATION_V1,
            PROVIDER_LAUNCH_BINDING_V1,
            EXECUTION_NODE_V1,
        )
    }
    def one(contract_type: str, field: str, value: str) -> Mapping[str, Any]:
        matches = [item.payload for item in projected[contract_type] if item.payload[field] == value]
        if len(matches) != 1:
            raise CompanyDepartmentLifecycleError("provider turn retry lifecycle is missing or ambiguous")
        return matches[0]
    terminal = one(
        PROVIDER_WORKER_IO_RECEIPT_V1, "receipt_id", str(receipt["terminal_io_receipt_id"]),
    )
    operation = one(PROVIDER_WORKER_OPERATION_V1, "operation_id", str(receipt["operation_id"]))
    launch = one(PROVIDER_LAUNCH_BINDING_V1, "launch_binding_id", str(receipt["launch_binding_id"]))
    agent = one(EXECUTION_NODE_V1, "execution_id", str(receipt["agent_execution_id"]))
    turn = one(EXECUTION_NODE_V1, "execution_id", str(receipt["turn_execution_id"]))
    exits = [
        item.payload for item in projected[PROVIDER_WORKER_IO_RECEIPT_V1]
        if (
            item.payload["phase"] == "process_exit_observed"
            and item.payload["launch_binding_id"] == receipt["launch_binding_id"]
            and item.payload["execution_id"] == receipt["turn_execution_id"]
            and item.payload["thread_id"] == receipt["thread_id"]
            and item.payload["turn_id"] == receipt["turn_id"]
        )
    ]
    if len(exits) != 1:
        raise CompanyDepartmentLifecycleError("provider turn retry lacks one exact process exit")
    try:
        validate_provider_turn_result_lifecycle(
            receipt, document, terminal, exits[0], operation, launch, agent, turn,
            recorded_at,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CompanyDepartmentLifecycleError(
            "provider turn retry result differs from exact lifecycle",
        ) from exc
    return _department_execution_status_result(
        record,
        execution,
        idempotent_replay=True,
    )


def _department_execution_idle_replay(
    record: LedgerTransactionRecord,
    *,
    execution_id: str,
    command_id: str,
    receipt: Mapping[str, Any],
    source_bytes: bytes,
    state_owner: CompanyStateOwner,
    recorded_at: str,
    result_bytes: bytes | None,
    result_media_type: str | None,
) -> ExecutionRuntimeStatusResult:
    wrappers = [_plain(member.event) for member in record.events]
    has_durable_result = len(wrappers) == 4
    if (
        record.reservations
        or str(record.receipt["state"]) != "committed"
        or str(record.request["command_id"]) != command_id
        or len(wrappers) not in {3, 4}
        or has_durable_result
        != (result_bytes is not None and result_media_type is not None)
    ):
        raise CompanyDepartmentLifecycleError(
            "engineering disposition retry differs from its durable command",
        )
    durable_receipt = validate_engineering_disposition_receipt(
        wrappers[0]["payload"],
    )
    durable_evidence = validate_evidence_record(wrappers[1]["payload"])
    try:
        execution = validate_execution_node(wrappers[2]["payload"])
    except ValueError as exc:
        raise CompanyDepartmentLifecycleError(
            "durable engineering disposition is invalid",
        ) from exc
    durable_result = (
        validate_work_result_receipt(wrappers[3]["payload"])
        if has_durable_result
        else None
    )
    if (
        durable_receipt
        != validate_engineering_disposition_receipt(receipt)
        or hashlib.sha256(source_bytes).hexdigest()
        != durable_receipt["raw_artifact"]["sha256"]
        or len(source_bytes)
        != durable_receipt["raw_artifact"]["size_bytes"]
        or durable_evidence
        != _engineering_disposition_evidence(durable_receipt)
        or execution["execution_id"] != execution_id
        or execution["engineering_status"] != "idle"
        or execution["runtime_status"] != "stopped"
        or execution["wait_reason"] != "park_ready"
        or execution["provenance"] != "agent_reported"
        or execution["observation"]
        != {"state": "known", "reason": "observed"}
        or not execution["evidence_ids"]
        or execution["evidence_ids"][-1]
        != durable_evidence["evidence_id"]
        or execution["updated_at"] != recorded_at
        or execution["last_event_at"] != recorded_at
        or wrappers[0]["event_id"]
        != (
            "engineering-disposition-receipt-"
            f"{durable_receipt['receipt_sha256']}"
        )
        or wrappers[0]["stream"] != "evidence"
        or wrappers[0]["event_type"]
        != "engineering_disposition.agent_reported"
        or wrappers[0]["recorded_at"] != recorded_at
        or wrappers[0]["provenance"] != "agent_reported"
        or wrappers[1]["event_id"] != durable_evidence["evidence_id"]
        or wrappers[1]["stream"] != "evidence"
        or wrappers[1]["event_type"]
        != "evidence.engineering_disposition.observed"
        or wrappers[1]["recorded_at"] != recorded_at
        or wrappers[1]["provenance"] != "agent_reported"
        or wrappers[2]["event_id"]
        != _department_execution_idle_event_id(
            execution_id,
            transaction_id=str(record.request["transaction_id"]),
            command_id=command_id,
        )
        or wrappers[2]["stream"] != "execution"
        or wrappers[2]["event_type"]
        != "execution.department_lead.idle"
        or wrappers[2]["recorded_at"] != recorded_at
        or wrappers[2]["provenance"] != "agent_reported"
        or (
            durable_result is not None
            and (
                durable_result["producer_execution_id"] != execution_id
                or durable_result["expected_execution_payload_sha256"]
                != durable_receipt["expected_execution_payload_sha256"]
                or durable_result["engineering_disposition_receipt_id"]
                != durable_receipt["receipt_id"]
                or durable_result["packet_id"]
                != durable_receipt["result_packet_id"]
                or durable_result["recorded_at"] != recorded_at
                or durable_result["result_ref"]["media_type"]
                != result_media_type
                or hashlib.sha256(cast(bytes, result_bytes)).hexdigest()
                != durable_result["result_ref"]["sha256"]
                or len(cast(bytes, result_bytes))
                != durable_result["result_ref"]["size_bytes"]
                or wrappers[3]["event_id"]
                != _work_definition_id(
                    {
                        "company_id": durable_result["company_id"],
                        "company_incarnation":
                            durable_result["company_incarnation"],
                        "lock_domain_generation":
                            durable_result["lock_domain_generation"],
                    },
                    "result-event",
                    str(record.request["transaction_id"]),
                )
                or wrappers[3]["stream"] != "evidence"
                or wrappers[3]["event_type"] != "work.result.recorded"
                or wrappers[3]["recorded_at"] != recorded_at
                or wrappers[3]["provenance"] != "AOI_verified"
            )
        )
    ):
        raise CompanyDepartmentLifecycleError(
            "engineering disposition retry differs from durable bytes",
        )
    try:
        if (
            state_owner.blobs.read(
                durable_receipt["raw_artifact"]["sha256"],
            )
            != source_bytes
        ):
            raise CompanyDepartmentLifecycleError(
                "durable engineering disposition source differs",
            )
    except (BlobStoreError, OSError) as exc:
        raise CompanyDepartmentLifecycleError(
            "durable engineering disposition source is unavailable",
        ) from exc
    if durable_result is not None:
        try:
            if (
                state_owner.blobs.read(
                    str(durable_result["result_ref"]["sha256"]),
                )
                != result_bytes
            ):
                raise CompanyDepartmentLifecycleError(
                    "durable registered work result differs",
                )
        except (BlobStoreError, OSError) as exc:
            raise CompanyDepartmentLifecycleError(
                "durable registered work result is unavailable",
            ) from exc
    return _department_execution_status_result(
        record,
        execution,
        idempotent_replay=True,
    )


def _fenced_chief_execution_stop_event_id(
    execution_id: str,
    *,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "execution_id": execution_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "transition": "fenced_chief_runtime_stopped",
    })
    return f"fenced-chief-execution-stop-{digest}"


def _current_chief_carrier_lost_event_id(
    execution_id: str,
    *,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "execution_id": execution_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "transition": "current_chief_carrier_lost",
    })
    return f"current-chief-carrier-lost-{digest}"


def _current_chief_execution_stop_event_id(
    execution_id: str,
    *,
    transaction_id: str,
    command_id: str,
) -> str:
    digest = company_contract_sha256({
        "execution_id": execution_id,
        "transaction_id": transaction_id,
        "command_id": command_id,
        "transition": "current_chief_runtime_stopped",
    })
    return f"current-chief-execution-stop-{digest}"


def _current_chief_execution_stop_replay(
    record: LedgerTransactionRecord,
    *,
    execution_id: str,
    command_id: str,
    provider_receipt: Mapping[str, Any],
    recorded_at: str,
) -> ExecutionRuntimeStatusResult:
    wrappers = [_plain(member.event) for member in record.events]
    if (
        record.reservations
        or str(record.receipt["state"]) != "committed"
        or str(record.request["command_id"]) != command_id
        or len(wrappers) != 4
    ):
        raise CompanyChiefTakeoverError(
            "current Chief stop retry differs from its durable command",
        )
    receipt = validate_provider_lifecycle_receipt(wrappers[0]["payload"])
    expected_receipt = validate_provider_lifecycle_receipt(provider_receipt)
    evidence = validate_evidence_record(wrappers[1]["payload"])
    try:
        carrier = validate_carrier_binding(wrappers[2]["payload"])
        execution = validate_execution_node(wrappers[3]["payload"])
    except ValueError as exc:
        raise CompanyChiefTakeoverError(
            "durable current Chief stop is invalid",
        ) from exc
    if (
        receipt != expected_receipt
        or receipt["event_kind"] != "execution_stopped"
        or receipt["dispatch_request_id"] is not None
        or receipt["dispatch_revision_id"] is not None
        or receipt["dispatch_revision"] is not None
        or receipt["provider_dispatch_id"] is not None
        or evidence != _provider_lifecycle_evidence(receipt)
        or carrier["carrier_id"] != receipt["carrier_id"]
        or carrier["state"] != "lost"
        or carrier["session_availability"] != "unavailable"
        or carrier["last_observed_at"] != recorded_at
        or execution["execution_id"] != execution_id
        or execution["carrier_id"] != carrier["carrier_id"]
        or execution["runtime_status"] != "stopped"
        or execution["wait_reason"] != "carrier_stopped"
        or execution["heartbeat_at"] is not None
        or execution["current_tool"] is not None
        or execution["receipt_id"] != receipt["receipt_id"]
        or not execution["evidence_ids"]
        or execution["evidence_ids"][-1] != evidence["evidence_id"]
        or execution["provenance"] != receipt["provenance"]
        or execution["observation"] != receipt["observation"]
        or execution["updated_at"] != recorded_at
        or execution["last_event_at"] != recorded_at
        or wrappers[2]["event_id"]
        != _current_chief_carrier_lost_event_id(
            execution_id,
            transaction_id=str(record.request["transaction_id"]),
            command_id=command_id,
        )
        or wrappers[2]["stream"] != "org"
        or wrappers[2]["event_type"] != "carrier.current_chief.lost"
        or wrappers[2]["recorded_at"] != recorded_at
        or wrappers[2]["provenance"] != receipt["provenance"]
        or wrappers[3]["event_id"]
        != _current_chief_execution_stop_event_id(
            execution_id,
            transaction_id=str(record.request["transaction_id"]),
            command_id=command_id,
        )
        or wrappers[3]["stream"] != "execution"
        or wrappers[3]["event_type"]
        != "execution.chief_current.stopped"
        or wrappers[3]["recorded_at"] != recorded_at
        or wrappers[3]["provenance"] != receipt["provenance"]
        or [item["event_type"] for item in wrappers[:2]]
        != [
            "provider.lifecycle.execution_stopped",
            "evidence.provider_lifecycle.observed",
        ]
    ):
        raise CompanyChiefTakeoverError(
            "current Chief stop retry differs from durable bytes",
        )
    return _department_execution_status_result(
        record,
        execution,
        idempotent_replay=True,
    )


def _fenced_chief_execution_stop_replay(
    record: LedgerTransactionRecord,
    *,
    execution_id: str,
    command_id: str,
    provider_receipt: Mapping[str, Any],
    recorded_at: str,
) -> ExecutionRuntimeStatusResult:
    wrappers = [_plain(member.event) for member in record.events]
    if (
        record.reservations
        or str(record.receipt["state"]) != "committed"
        or str(record.request["command_id"]) != command_id
        or len(wrappers) != 3
    ):
        raise CompanyChiefTakeoverError(
            "fenced Chief stop retry differs from its durable command",
        )
    receipt = validate_provider_lifecycle_receipt(wrappers[0]["payload"])
    expected_receipt = validate_provider_lifecycle_receipt(provider_receipt)
    evidence = validate_evidence_record(wrappers[1]["payload"])
    wrapper = wrappers[2]
    try:
        execution = validate_execution_node(wrapper["payload"])
    except ValueError as exc:
        raise CompanyChiefTakeoverError(
            "durable fenced Chief execution stop is invalid",
        ) from exc
    if (
        execution["execution_id"] != execution_id
        or receipt != expected_receipt
        or receipt["event_kind"] != "execution_stopped"
        or receipt["dispatch_request_id"] is not None
        or receipt["dispatch_revision_id"] is not None
        or receipt["dispatch_revision"] is not None
        or receipt["provider_dispatch_id"] is not None
        or evidence != _provider_lifecycle_evidence(receipt)
        or execution["engineering_status"] != "waiting"
        or execution["runtime_status"] != "stopped"
        or execution["wait_reason"] != "fenced_read_only"
        or execution["heartbeat_at"] is not None
        or execution["current_tool"] is not None
        or execution["receipt_id"] != receipt["receipt_id"]
        or not execution["evidence_ids"]
        or execution["evidence_ids"][-1] != evidence["evidence_id"]
        or execution["provenance"] != receipt["provenance"]
        or execution["observation"] != receipt["observation"]
        or execution["updated_at"] != recorded_at
        or execution["last_event_at"] != recorded_at
        or wrapper["event_id"]
        != _fenced_chief_execution_stop_event_id(
            execution_id,
            transaction_id=str(record.request["transaction_id"]),
            command_id=command_id,
        )
        or wrapper["stream"] != "execution"
        or wrapper["event_type"] != "execution.chief_fenced.stopped"
        or wrapper["recorded_at"] != recorded_at
        or wrapper["provenance"] != receipt["provenance"]
        or [item["event_type"] for item in wrappers[:2]]
        != [
            "provider.lifecycle.execution_stopped",
            "evidence.provider_lifecycle.observed",
        ]
    ):
        raise CompanyChiefTakeoverError(
            "fenced Chief stop retry differs from durable bytes",
        )
    return _department_execution_status_result(
        record,
        execution,
        idempotent_replay=True,
    )


def _execution_registration_current_event_id(
    registration_id: str,
    execution_id: str,
) -> str:
    digest = company_contract_sha256({
        "registration_id": registration_id,
        "execution_id": execution_id,
        "event_type": "execution.registered.current",
    })
    return f"execution-registration-current-{digest}"


def _execution_registration_event(
    node: Mapping[str, Any],
) -> dict[str, Any]:
    registration_id = node["registration_id"]
    if registration_id is None:
        raise CompanyExecutionRegistrationError(
            "execution registration identity is absent",
        )
    payload: dict[str, Any] = {}
    value = {
        "contract_type": EXECUTION_EVENT_V1,
        "schema_version": 1,
        "company_id": node["company_id"],
        "company_incarnation": node["company_incarnation"],
        "lock_domain_generation": node["lock_domain_generation"],
        "event_id": registration_id,
        "execution_id": node["execution_id"],
        "execution_kind": node["execution_kind"],
        "display_name": node["display_name"],
        "parent_execution_id": node["parent_execution_id"],
        "execution_depth": node["execution_depth"],
        "execution_path": node["execution_path"],
        "task_id": node["task_id"],
        "packet_id": node["packet_id"],
        "thread_id": node["thread_id"],
        "turn_id": node["turn_id"],
        "agent_id": node["agent_id"],
        "job_id": node["job_id"],
        "dispatch_id": node["dispatch_id"],
        "registration_id": registration_id,
        "receipt_id": node["receipt_id"],
        "provider": node["provider"],
        "model": node["model"],
        "effort": node["effort"],
        "carrier_id": node["carrier_id"],
        "delegation_depth": node["delegation_depth"],
        "event_type": "execution.registered",
        "recorded_at": node["created_at"],
        "engineering_status": node["engineering_status"],
        "runtime_status": node["runtime_status"],
        "attention_overlays": node["attention_overlays"],
        "payload": payload,
        "payload_sha256": company_contract_sha256(payload),
        "evidence_ids": node["evidence_ids"],
        "provenance": node["provenance"],
        "observation": node["observation"],
    }
    try:
        return validate_execution_event(value)
    except ValueError as exc:
        raise CompanyExecutionRegistrationError(
            "execution registration event is invalid",
        ) from exc


def _execution_registration_result_from_record(
    record: LedgerTransactionRecord,
    execution: Mapping[str, Any],
    evidence: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    current_event_id: str,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
    idempotent_replay: bool,
) -> ExecutionRuntimeStatusResult:
    members = record.events if record.events else record.reservations
    wrappers = [_plain(member.event) for member in members]
    expected = [
        (
            str(evidence["evidence_id"]),
            "evidence",
            "evidence.execution_registration.observed",
            evidence,
            str(evidence["provenance"]),
        ),
        (
            str(execution["registration_id"]),
            "execution",
            "execution.registered",
            event,
            str(execution["provenance"]),
        ),
        (
            current_event_id,
            "execution",
            "execution.registered.current",
            execution,
            str(execution["provenance"]),
        ),
    ]
    if (
        record.reservations
        or str(record.receipt["state"]) != "committed"
        or str(record.request["transaction_id"]) != transaction_id
        or str(record.request["command_id"]) != command_id
        or len(wrappers) != len(expected)
    ):
        raise CompanyExecutionRegistrationError(
            "durable execution registration membership differs",
        )
    for wrapper, (
        event_id,
        stream,
        event_type,
        payload,
        provenance,
    ) in zip(wrappers, expected, strict=True):
        if (
            wrapper["event_id"] != event_id
            or wrapper["stream"] != stream
            or wrapper["event_type"] != event_type
            or wrapper["recorded_at"] != recorded_at
            or wrapper["payload"] != _plain(payload)
            or wrapper["provenance"] != provenance
        ):
            raise CompanyExecutionRegistrationError(
                "durable execution registration bytes differ",
            )
    return _department_execution_status_result(
        record,
        execution,
        idempotent_replay=idempotent_replay,
    )


_EXTERNAL_JOB_EXECUTION_STATUSES = {
    "queued": ("waiting", "stopped"),
    "running": ("active", "running"),
    "completed": ("completed", "stopped"),
    "failed_known": ("completed", "stopped"),
    "effect_unknown": ("blocked", "unknown"),
    "reconcile_required": ("blocked", "unknown"),
    "aborted": ("cancelled", "stopped"),
    "unknown": ("unknown", "unknown"),
}
_EXTERNAL_JOB_ALLOWED_TRANSITIONS = {
    "queued": frozenset({"running", "effect_unknown", "aborted"}),
    "running": frozenset({
        "completed",
        "failed_known",
        "effect_unknown",
    }),
    "effect_unknown": frozenset({
        "reconcile_required",
        "completed",
        "failed_known",
    }),
    "reconcile_required": frozenset({"completed", "failed_known"}),
    "unknown": frozenset({"effect_unknown"}),
}
_EXTERNAL_JOB_PRIOR_INTENT_STATES = {
    ("queued", "running"): frozenset({"in_flight"}),
    ("queued", "effect_unknown"): frozenset({"in_flight"}),
    ("queued", "aborted"): frozenset({"admitted"}),
    ("running", "completed"): frozenset({"in_flight"}),
    ("running", "failed_known"): frozenset({"in_flight"}),
    ("running", "effect_unknown"): frozenset({"in_flight"}),
    ("effect_unknown", "reconcile_required"): frozenset({"effect_unknown"}),
    ("effect_unknown", "completed"): frozenset({"effect_unknown"}),
    ("effect_unknown", "failed_known"): frozenset({"effect_unknown"}),
    ("reconcile_required", "completed"): frozenset({"reconcile_required"}),
    ("reconcile_required", "failed_known"): frozenset({"reconcile_required"}),
    ("unknown", "effect_unknown"): frozenset({"unknown"}),
}
_EXTERNAL_JOB_MUTATION_STATES = {
    "running": "in_flight",
    "completed": "committed",
    "failed_known": "failed_known",
    "effect_unknown": "effect_unknown",
    "reconcile_required": "reconcile_required",
    "aborted": "aborted",
}


def _current_payload(
    state: CompanyStateOwner,
    contract_type: str,
    object_key: str,
) -> dict[str, Any] | None:
    matches = [
        dict(_plain(item.payload))
        for item in state.objects(contract_type=contract_type)
        if item.object_key == object_key
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise CompanyExternalJobError(
            f"durable {contract_type} identity is ambiguous",
        )
    return matches[0]


def _required_current_external_job(
    state: CompanyStateOwner,
    job_id: str,
) -> dict[str, Any]:
    job = _current_payload(state, EXTERNAL_JOB_V1, job_id)
    if job is None:
        raise CompanyExternalJobError("external job is unavailable")
    try:
        return validate_external_job(job)
    except ValueError as exc:
        raise CompanyExternalJobError(
            "durable external job is invalid",
        ) from exc


def _required_current_job_intent(
    state: CompanyStateOwner,
    intent_id: str,
) -> dict[str, Any]:
    intent = _current_payload(state, MUTATION_INTENT_V1, intent_id)
    if intent is None:
        raise CompanyExternalJobError(
            "external job MutationIntent is unavailable",
        )
    try:
        current = validate_mutation_intent(intent)
    except ValueError as exc:
        raise CompanyExternalJobError(
            "durable external job MutationIntent is invalid",
        ) from exc
    if current["mutation_kind"] != "job.start":
        raise CompanyExternalJobError(
            "external job MutationIntent kind differs",
        )
    return current


def _required_current_job_execution(
    state: CompanyStateOwner,
    job_id: str,
) -> dict[str, Any]:
    matches = [
        dict(_plain(item.payload))
        for item in state.objects(contract_type=EXECUTION_NODE_V1)
        if (
            item.payload["execution_kind"] == "job"
            and item.payload["job_id"] == job_id
        )
    ]
    if len(matches) != 1:
        raise CompanyExternalJobError(
            "external job execution identity is unavailable or ambiguous",
        )
    try:
        return validate_execution_node(matches[0])
    except ValueError as exc:
        raise CompanyExternalJobError(
            "durable external job execution is invalid",
        ) from exc


def _external_job_event_id(transaction_id: str, label: str) -> str:
    digest = company_contract_sha256({
        "transaction_id": transaction_id,
        "label": label,
        "lifecycle": "external_job_v1",
    })
    return f"external-job-{label}-{digest[:32]}"


def _external_job_effect_draft(
    receipt: Mapping[str, Any],
) -> CompanyEventDraft:
    digest = company_contract_sha256({
        "company_id": receipt["company_id"],
        "company_incarnation": receipt["company_incarnation"],
        "lock_domain_generation": receipt["lock_domain_generation"],
        "receipt_id": receipt["receipt_id"],
        "source_event_id": receipt["source_event_id"],
    })
    return CompanyEventDraft(
        event_id=f"external-job-effect-receipt-{digest[:40]}",
        event_type=(
            f"external_job.effect."
            f"{receipt['observed_job_state']}.observed"
        ),
        recorded_at=str(receipt["observed_at"]),
        payload=receipt,
        provenance=str(receipt["provenance"]),
    )


def _external_job_execution(
    owner: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    execution_id: str,
    display_name: str,
    objective: str,
) -> dict[str, Any]:
    engineering_status, runtime_status = (
        _EXTERNAL_JOB_EXECUTION_STATUSES[str(job["state"])]
    )
    candidate = {
        "contract_type": EXECUTION_NODE_V1,
        "schema_version": 1,
        "company_id": job["company_id"],
        "company_incarnation": job["company_incarnation"],
        "lock_domain_generation": job["lock_domain_generation"],
        "execution_id": execution_id,
        "execution_kind": "job",
        "display_name": display_name,
        "organization_node_id": owner["organization_node_id"],
        "department_id": owner["department_id"],
        "parent_execution_id": owner["execution_id"],
        "execution_depth": int(owner["execution_depth"]) + 1,
        "execution_path": [*owner["execution_path"], execution_id],
        "task_id": owner["task_id"],
        "packet_id": owner["packet_id"],
        "thread_id": None,
        "turn_id": None,
        "agent_id": None,
        "job_id": job["job_id"],
        "dispatch_id": None,
        "registration_id": None,
        "receipt_id": None,
        "provider": "external",
        "model": None,
        "effort": None,
        "carrier_id": None,
        "role": "external_job",
        "delegation_depth": owner["delegation_depth"],
        "engineering_status": engineering_status,
        "runtime_status": runtime_status,
        "attention_overlays": [],
        "objective": objective,
        "phase": "external_job",
        "created_at": job["created_at"],
        "updated_at": job["updated_at"],
        "last_event_at": job["updated_at"],
        "heartbeat_at": None,
        "wait_reason": "queued",
        "current_tool": None,
        "terminal_at": job["terminal_at"],
        "usage_cursor": 0,
        "job_ids": [],
        "evidence_ids": [],
        "provenance": job["actor_authority"]["provenance"],
        "observation": job["observation"],
    }
    try:
        return validate_execution_node(candidate)
    except ValueError as exc:
        raise CompanyExternalJobError(
            "external job execution is invalid",
        ) from exc


def _external_job_execution_revision(
    execution: Mapping[str, Any],
    job: Mapping[str, Any],
) -> dict[str, Any]:
    engineering_status, runtime_status = (
        _EXTERNAL_JOB_EXECUTION_STATUSES[str(job["state"])]
    )
    state = str(job["state"])
    wait_reason = {
        "running": None,
        "completed": None,
        "failed_known": "failed_known",
        "effect_unknown": "effect_unknown",
        "reconcile_required": "reconcile_required",
        "aborted": "aborted_before_launch",
        "unknown": "outcome_unknown",
        "queued": "queued",
    }[state]
    attention = (
        ["coverage_degraded"]
        if state in {"effect_unknown", "reconcile_required", "unknown"}
        else []
    )
    candidate = {
        **execution,
        "engineering_status": engineering_status,
        "runtime_status": runtime_status,
        "attention_overlays": attention,
        "updated_at": job["updated_at"],
        "last_event_at": job["updated_at"],
        "heartbeat_at": (
            job["updated_at"] if state == "running" else None
        ),
        "wait_reason": wait_reason,
        "current_tool": None,
        "terminal_at": job["terminal_at"],
        "provenance": job["actor_authority"]["provenance"],
        "observation": job["observation"],
    }
    try:
        return validate_execution_node(candidate)
    except ValueError as exc:
        raise CompanyExternalJobError(
            "external job execution revision is invalid",
        ) from exc


def _external_job_execution_event(
    execution: Mapping[str, Any],
    *,
    job_state: str,
    mutation_state: str,
    event_id: str,
) -> dict[str, Any]:
    payload = {
        "job_state": job_state,
        "mutation_state": mutation_state,
    }
    candidate = {
        "contract_type": EXECUTION_EVENT_V1,
        "schema_version": 1,
        "company_id": execution["company_id"],
        "company_incarnation": execution["company_incarnation"],
        "lock_domain_generation": execution["lock_domain_generation"],
        "event_id": event_id,
        "execution_id": execution["execution_id"],
        "execution_kind": execution["execution_kind"],
        "display_name": execution["display_name"],
        "parent_execution_id": execution["parent_execution_id"],
        "execution_depth": execution["execution_depth"],
        "execution_path": execution["execution_path"],
        "task_id": execution["task_id"],
        "packet_id": execution["packet_id"],
        "thread_id": execution["thread_id"],
        "turn_id": execution["turn_id"],
        "agent_id": execution["agent_id"],
        "job_id": execution["job_id"],
        "dispatch_id": execution["dispatch_id"],
        "registration_id": execution["registration_id"],
        "receipt_id": execution["receipt_id"],
        "provider": execution["provider"],
        "model": execution["model"],
        "effort": execution["effort"],
        "carrier_id": execution["carrier_id"],
        "delegation_depth": execution["delegation_depth"],
        "event_type": f"external_job.{job_state}",
        "recorded_at": execution["updated_at"],
        "engineering_status": execution["engineering_status"],
        "runtime_status": execution["runtime_status"],
        "attention_overlays": execution["attention_overlays"],
        "payload": payload,
        "payload_sha256": company_contract_sha256(payload),
        "evidence_ids": execution["evidence_ids"],
        "provenance": execution["provenance"],
        "observation": execution["observation"],
    }
    try:
        return validate_execution_event(candidate)
    except ValueError as exc:
        raise CompanyExternalJobError(
            "external job execution event is invalid",
        ) from exc


def _external_job_result_from_record(
    state_owner: CompanyStateOwner,
    record: LedgerTransactionRecord,
    *,
    job_id: str,
    expected_state: str,
    transaction_id: str,
    command_id: str,
    recorded_at: str,
    expected_mutation_state: str | None = None,
    expected_job_fields: Mapping[str, Any] | None = None,
    expected_effect_receipt: Mapping[str, Any] | None = None,
    expected_external_handle: Mapping[str, Any] | None = None,
    owner_execution_id: str | None = None,
    job_execution_id: str | None = None,
    mutation_intent_id: str | None = None,
    expected_command_sha256: str | None = None,
    expected_command_size: int | None = None,
    expected_command_media_type: str | None = None,
    expected_scope_sha256: str | None = None,
    expected_display_name: str | None = None,
    expected_objective: str | None = None,
    expected_authority_grant_id: str | None = None,
    expected_grant_expires_at: str | None = None,
    idempotent_replay: bool,
) -> ExternalJobLifecycleResult:
    if (
        record.reservations
        or str(record.receipt["state"]) != "committed"
        or str(record.request["transaction_id"]) != transaction_id
        or str(record.request["command_id"]) != command_id
        or any(
            str(member.event["recorded_at"]) != recorded_at
            for member in record.events
        )
    ):
        raise CompanyExternalJobError(
            "durable external job transaction differs",
        )
    payloads = [
        _plain(member.event["payload"])
        for member in record.events
    ]
    jobs = [
        validate_external_job(payload)
        for payload in payloads
        if payload.get("contract_type") == EXTERNAL_JOB_V1
    ]
    intents = [
        validate_mutation_intent(payload)
        for payload in payloads
        if (
            payload.get("contract_type") == MUTATION_INTENT_V1
            and payload.get("mutation_kind") == "job.start"
        )
    ]
    executions = [
        validate_execution_node(payload)
        for payload in payloads
        if (
            payload.get("contract_type") == EXECUTION_NODE_V1
            and payload.get("execution_kind") == "job"
        )
    ]
    effect_receipts = [
        validate_external_job_effect_receipt(payload)
        for payload in payloads
        if payload.get("contract_type")
        == EXTERNAL_JOB_EFFECT_RECEIPT_V1
    ]
    if len(intents) != 1:
        raise CompanyExternalJobError(
            "durable external job MutationIntent differs",
        )
    intent = intents[0]
    if jobs:
        if len(jobs) != 1 or jobs[0]["job_id"] != job_id:
            raise CompanyExternalJobError(
                "durable external job identity differs",
            )
        job = jobs[0]
    else:
        job = _required_current_external_job(state_owner, job_id)
    if executions:
        if len(executions) != 1:
            raise CompanyExternalJobError(
                "durable external job execution differs",
            )
        execution = executions[0]
    else:
        execution = _required_current_job_execution(state_owner, job_id)
    mutation_state = (
        str(intent["state"])
        if expected_mutation_state is None
        else expected_mutation_state
    )
    if (
        (jobs and job["state"] != expected_state)
        or intent["state"] != mutation_state
        or intent["intent_id"] != job["mutation_intent_id"]
        or execution["job_id"] != job_id
        or (
            owner_execution_id is not None
            and job["owner_execution_id"] != owner_execution_id
        )
        or (
            job_execution_id is not None
            and execution["execution_id"] != job_execution_id
        )
        or (
            mutation_intent_id is not None
            and intent["intent_id"] != mutation_intent_id
        )
    ):
        raise CompanyExternalJobError(
            "durable external job lifecycle bytes differ",
        )
    if expected_job_fields is not None and any(
        job[field] != _plain(expected)
        for field, expected in expected_job_fields.items()
    ):
        raise CompanyExternalJobError(
            "durable external job observation or effect bytes differ",
        )
    if expected_effect_receipt is None:
        if effect_receipts:
            raise CompanyExternalJobError(
                "durable external job effect receipt is unexpected",
            )
    else:
        expected_receipt = validate_external_job_effect_receipt(
            expected_effect_receipt,
        )
        expected_handle = (
            None
            if expected_external_handle is None
            else _plain(expected_external_handle)
        )
        if (
            len(effect_receipts) != 1
            or effect_receipts[0] != expected_receipt
            or expected_receipt["job_id"] != job_id
            or expected_receipt["mutation_intent_id"]
            != job["mutation_intent_id"]
            or expected_receipt["command_id"] != job["command_id"]
            or expected_receipt["transaction_id"] != transaction_id
            or expected_receipt["transition_command_id"] != command_id
            or expected_receipt["observed_at"] != recorded_at
            or expected_receipt["observed_job_state"] != expected_state
            or job["external_handle"] != expected_handle
            or (
                expected_state in {"running", "aborted"}
                and job["effect_evidence"]
            )
            or (
                expected_state not in {"running", "aborted"}
                and (
                    not job["effect_evidence"]
                    or job["effect_evidence"][-1]
                    != expected_receipt["raw_artifact"]
                )
            )
            or job["reconcile_ref"]
            != (
                expected_receipt["reconciliation_id"]
                if expected_state
                in {"effect_unknown", "reconcile_required"}
                else None
            )
        ):
            raise CompanyExternalJobError(
                "durable external job effect receipt differs",
            )
    command_blob = job["command_blob"]
    if (
        expected_command_sha256 is not None
        and command_blob["sha256"] != expected_command_sha256
    ) or (
        expected_command_size is not None
        and command_blob["size_bytes"] != expected_command_size
    ) or (
        expected_command_media_type is not None
        and command_blob["media_type"] != expected_command_media_type
    ) or (
        expected_scope_sha256 is not None
        and job["scope_sha256"] != expected_scope_sha256
    ) or (
        expected_display_name is not None
        and execution["display_name"] != expected_display_name
    ) or (
        expected_objective is not None
        and execution["objective"] != expected_objective
    ):
        raise CompanyExternalJobError(
            "durable external job command or display bytes differ",
        )
    if (
        expected_authority_grant_id is not None
        or expected_grant_expires_at is not None
    ):
        grants = [
            payload
            for payload in payloads
            if payload.get("contract_type") == AUTHORITY_GRANT_V1
        ]
        if grants:
            if len(grants) != 1:
                raise CompanyExternalJobError(
                    "durable external job authority grant differs",
                )
            grant = validate_authority_grant(grants[0])
        else:
            persisted_grant = _current_payload(
                state_owner,
                AUTHORITY_GRANT_V1,
                str(expected_authority_grant_id),
            )
            if persisted_grant is None:
                raise CompanyExternalJobError(
                    "durable external job authority grant is unavailable",
                )
            grant = validate_authority_grant(persisted_grant)
        if (
            grant["grant_id"] != expected_authority_grant_id
            or grant["expires_at"] != expected_grant_expires_at
            or authority_from_grant(grant) != job["actor_authority"]
        ):
            raise CompanyExternalJobError(
                "durable external job authority bytes differ",
            )
    return ExternalJobLifecycleResult(
        job_id=job_id,
        job_state=expected_state,
        owner_execution_id=str(job["owner_execution_id"]),
        job_execution_id=str(execution["execution_id"]),
        mutation_intent_id=str(intent["intent_id"]),
        mutation_state=mutation_state,
        transaction_id=transaction_id,
        command_id=command_id,
        global_sequence=record.global_sequence,
        idempotent_replay=idempotent_replay,
    )


def _department_execution_status_result(
    record: LedgerTransactionRecord,
    execution: Mapping[str, Any],
    *,
    idempotent_replay: bool,
) -> ExecutionRuntimeStatusResult:
    return ExecutionRuntimeStatusResult(
        execution_id=str(execution["execution_id"]),
        engineering_status=str(execution["engineering_status"]),
        runtime_status=str(execution["runtime_status"]),
        transaction_id=str(record.request["transaction_id"]),
        command_id=str(record.request["command_id"]),
        global_sequence=record.global_sequence,
        idempotent_replay=idempotent_replay,
    )


def _takeover_seed(
    binding: Mapping[str, Any],
    known_carrier: Mapping[str, Any],
    *,
    expected_chief_id: str,
    expected_term: int,
    expected_epoch: int,
    expected_head_sha256: str,
    objective_sha256: str,
    scope_sha256: str,
    nonce_sha256: str,
    issued_at: str,
    expires_at: str,
    user_action_ref: str,
) -> dict[str, Any]:
    return {
        **_plain(binding),
        "known_carrier": _plain(known_carrier),
        "expected_chief_id": expected_chief_id,
        "expected_term": expected_term,
        "expected_epoch": expected_epoch,
        "expected_head_sha256": expected_head_sha256,
        "objective_sha256": objective_sha256,
        "scope_sha256": scope_sha256,
        "nonce_sha256": nonce_sha256,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "user_action_ref": user_action_ref,
    }


def _takeover_ids(seed: Mapping[str, Any]) -> dict[str, str]:
    digest = company_contract_sha256(_plain(seed))
    labels = (
        "capability",
        "consumption",
        "transaction",
        "command",
        "grant",
        "execution",
        "capability_event",
        "receipt_event",
        "term_event",
        "grant_event",
        "prior-carrier_event",
        "prior-execution_event",
        "contender-carrier_event",
        "execution_event",
    )
    return {
        label: f"takeover-{label.replace('_', '-')}-"
        f"{company_contract_sha256({'seed_sha256': digest, 'label': label})[:24]}"
        for label in labels
    }


def _authority_grant(
    binding: Mapping[str, Any],
    *,
    grant_id: str,
    actor_id: str,
    actor_kind: str,
    carrier_id: str | None,
    chief_epoch: int | None,
    permissions: list[str],
    bootstrap_at: str,
    grant_expires_at: str,
    term: int = 1,
    scope_sha256: str | None = None,
) -> dict[str, Any]:
    unsigned = {
        "contract_type": AUTHORITY_GRANT_V1,
        "schema_version": 1,
        **binding,
        "grant_id": grant_id,
        "actor_id": actor_id,
        "actor_kind": actor_kind,
        "carrier_id": carrier_id,
        "chief_epoch": chief_epoch,
        "term": term,
        "authority_state": "active",
        "permissions": permissions,
        "scope_sha256": (
            company_contract_sha256(
                {"scope": "company.mutate", "actor_id": actor_id},
            )
            if scope_sha256 is None
            else scope_sha256
        ),
        "issued_at": bootstrap_at,
        "expires_at": grant_expires_at,
        "provenance": "AOI_verified",
    }
    return {**unsigned, "grant_sha256": company_contract_sha256(unsigned)}


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(member) for key, member in value.items()}
    if isinstance(value, tuple):
        return [_plain(member) for member in value]
    return value


def _blob_ref(sha256: str, size_bytes: int, media_type: str) -> dict[str, Any]:
    return {"contract_type": BLOB_REF_V1, "schema_version": 1, "sha256": sha256,
            "size_bytes": size_bytes, "media_type": media_type,
            "availability": "available"}


def _work_definition_id(
    binding: Mapping[str, Any],
    label: str,
    transaction_id: str,
) -> str:
    digest = hashlib.sha256(canonical_company_json_bytes({
        **dict(binding),
        "label": label,
        "transaction_id": transaction_id,
    })).hexdigest()
    return f"work-{label}-{digest[:24]}"


def _require_durable_work_definition_chief_fence(
    record: LedgerTransactionRecord,
    *,
    chief_id: str,
    carrier_id: str,
    term: int,
    epoch: int,
) -> None:
    request = _plain(record.request)
    authority = request.get("actor_authority")
    if (
        not isinstance(authority, Mapping)
        or authority.get("actor_kind") != "chief"
        or authority.get("actor_id") != chief_id
        or authority.get("carrier_id") != carrier_id
        or authority.get("term") != term
        or authority.get("chief_epoch") != epoch
        or authority.get("authority_state") != "active"
        or "company.mutate" not in authority.get("permissions", ())
    ):
        raise CompanyWorkDefinitionError(
            "durable work definition Chief fence differs",
        )


def _work_definition_result_from_record(
    record: LedgerTransactionRecord,
    *,
    task: Mapping[str, Any],
    packet: Mapping[str, Any],
    transaction_id: str,
    command_id: str,
    recorded_at: str,
    idempotent_replay: bool,
) -> WorkDefinitionRegistrationResult:
    request = _plain(record.request)
    receipt = _plain(record.receipt)
    wrappers = [_plain(member.event) for member in record.events]
    task_events = [
        wrapper
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == TASK_REVISION_V1
    ]
    packet_events = [
        wrapper
        for wrapper in wrappers
        if wrapper["payload"].get("contract_type") == WORK_PACKET_V1
    ]
    if (
        record.reservations
        or receipt.get("state") != "committed"
        or request.get("transaction_id") != transaction_id
        or request.get("command_id") != command_id
        or len(packet_events) != 1
        or len(task_events) not in {0, 1}
        or len(wrappers) != len(task_events) + len(packet_events)
        or packet_events[0]["payload"] != dict(packet)
        or (
            task_events
            and task_events[0]["payload"] != dict(task)
        )
        or any(
            wrapper["recorded_at"] != recorded_at
            or wrapper["provenance"] != "AOI_verified"
            for wrapper in wrappers
        )
    ):
        raise CompanyWorkDefinitionError(
            "durable work definition transaction differs",
        )
    return WorkDefinitionRegistrationResult(
        task_id=str(task["task_id"]),
        task_revision_id=str(task["task_revision_id"]),
        packet_id=str(packet["packet_id"]),
        transaction_id=transaction_id,
        command_id=command_id,
        global_sequence=record.global_sequence,
        idempotent_replay=idempotent_replay,
    )


def _work_definition_enforcement_result_from_record(
    record: LedgerTransactionRecord,
    *,
    transaction_id: str,
    command_id: str,
    activated_at: str,
    idempotent_replay: bool,
) -> WorkDefinitionEnforcementResult:
    wrappers = [_plain(member.event) for member in record.events]
    try:
        gate = validate_work_definition_enforcement(
            wrappers[0]["payload"],
        )
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise CompanyWorkDefinitionError(
            "durable work definition enforcement is invalid",
        ) from exc
    if (
        record.reservations
        or record.receipt["state"] != "committed"
        or record.request["transaction_id"] != transaction_id
        or record.request["command_id"] != command_id
        or len(wrappers) != 1
        or wrappers[0]["event_id"]
        != _work_definition_id(
            {
                "company_id": gate["company_id"],
                "company_incarnation": gate["company_incarnation"],
                "lock_domain_generation": gate["lock_domain_generation"],
            },
            "enforcement-event",
            transaction_id,
        )
        or wrappers[0]["stream"] != "org"
        or wrappers[0]["event_type"]
        != "work.definition.enforcement.activated"
        or wrappers[0]["recorded_at"] != activated_at
        or wrappers[0]["provenance"] != "AOI_verified"
        or gate["activated_at"] != activated_at
    ):
        raise CompanyWorkDefinitionError(
            "durable work definition enforcement differs",
        )
    return WorkDefinitionEnforcementResult(
        gate_id=str(gate["gate_id"]),
        mode=str(gate["mode"]),
        transaction_id=transaction_id,
        command_id=command_id,
        global_sequence=record.global_sequence,
        idempotent_replay=idempotent_replay,
    )


def _telemetry_id(binding: Mapping[str, Any], label: str, *parts: str) -> str:
    return telemetry_id(binding, label, *parts)


def _unknown_drop(reason: str) -> dict[str, Any]:
    return unknown_drop(reason)


def _coverage_event_kinds(provider: str, source_class: str, surface: str) -> list[str]:
    return coverage_event_kinds(provider, source_class, surface)


def _automatic_coverage_state(
    outcome: str, prior_sequence: int | None, intake_sequence: int,
    *, prior: Mapping[str, Any] | None,
) -> tuple[str, str, dict[str, Any]]:
    return automatic_coverage_state(
        outcome,
        prior_sequence,
        intake_sequence,
        prior=prior,
    )


def _provider_telemetry_receipt_payload(
    binding: Mapping[str, Any], *, normalized: NormalizedTelemetry,
    raw_artifact: Mapping[str, Any], join: Mapping[str, Any], receipt_id: str,
    adapter_instance_id: str, adapter_event_id: str, intake_sequence: int,
    transaction_id: str, command_id: str, received_at: str,
) -> dict[str, Any]:
    payload = {
        "contract_type": PROVIDER_TELEMETRY_RECEIPT_V1, "schema_version": 1,
        **binding, "transaction_id": transaction_id, "command_id": command_id,
        "receipt_id": receipt_id, "adapter_instance_id": adapter_instance_id,
        "adapter_event_id": adapter_event_id, "intake_sequence": intake_sequence,
        "provider": normalized.provider, "source_class": normalized.source_class,
        "parser_id": normalized.parser_id, "parser_version": normalized.parser_version,
        "parse_outcome": normalized.parse_outcome,
        "normalized_kind": normalized.normalized_kind,
        "facts": telemetry_facts_payload(normalized),
        "provider_native_relation": provider_native_relation_payload(normalized),
        "dispatch_join": dict(join), "received_at": received_at,
        "raw_artifact": dict(raw_artifact), "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
        "receipt_sha256": ZERO_SHA256,
    }
    payload["receipt_sha256"] = company_contract_sha256({
        key: value for key, value in payload.items() if key != "receipt_sha256"
    })
    return validate_provider_telemetry_receipt(payload)


def _token_vector_payload(value: Any) -> dict[str, dict[str, Any]]:
    return {
        "input": {"present": True, "tokens": value.input},
        "cache_read": {"present": True, "tokens": value.cache_read},
        "cache_creation": {"present": value.cache_creation is not None, "tokens": value.cache_creation},
        "output": {"present": True, "tokens": value.output},
        "reasoning_output": {"present": True, "tokens": value.reasoning_output},
        "total": {"present": True, "tokens": value.total},
    }


def _usage_counter_sample_payload(
    binding: Mapping[str, Any], *, normalized: NormalizedTelemetry,
    raw_artifact: Mapping[str, Any], receipt: Mapping[str, Any], sample_id: str,
    adapter_instance_id: str, adapter_event_id: str, intake_sequence: int,
    received_at: str,
) -> dict[str, Any]:
    sample = normalized.raw_cumulative_tokens
    if sample is None:
        raise CompanyTelemetryIngestError("usage sample is absent")
    facts = telemetry_facts_payload(normalized)
    if any(facts[name]["quality"] != "observed" for name in ("thread_id", "turn_id")):
        raise CompanyTelemetryIngestError("usage sample lacks exact thread/turn identity")
    payload = {
        "contract_type": USAGE_COUNTER_SAMPLE_V1, "schema_version": 1,
        **binding, "sample_id": sample_id, "telemetry_receipt_id": receipt["receipt_id"],
        "telemetry_receipt_sha256": receipt["receipt_sha256"],
        "adapter_instance_id": adapter_instance_id, "adapter_event_id": adapter_event_id,
        "intake_sequence": intake_sequence, "provider": normalized.provider,
        "thread_id": facts["thread_id"]["value"], "turn_id": facts["turn_id"]["value"],
        "counter_scope_id": facts["thread_id"]["value"], "provider_sequence": None,
        "counting_semantics": "non_additive_cumulative",
        "total_token_vector": _token_vector_payload(sample.total),
        "last_token_vector": _token_vector_payload(sample.last),
        "model_context_window": {"present": sample.model_context_window is not None, "value": sample.model_context_window},
        "provenance_facts": {name: facts[name] for name in (
            "actual_provider", "actual_model", "actual_effort", "actual_role", "routing",
        )},
        "received_at": received_at, "raw_artifact": dict(raw_artifact),
        "provenance": "adapter_receipt_persisted",
        "observation": {"state": "known", "reason": "observed"},
        "sample_sha256": ZERO_SHA256,
    }
    payload["sample_sha256"] = company_contract_sha256({
        key: value for key, value in payload.items() if key != "sample_sha256"
    })
    return validate_usage_counter_sample(payload)


def _telemetry_result_from_record(
    record: LedgerTransactionRecord, *, idempotent_replay: bool,
) -> ProviderTelemetryIngestResult:
    payloads = [_plain(event.event["payload"]) for event in record.events]
    receipts = [validate_provider_telemetry_receipt(value) for value in payloads if value.get("contract_type") == PROVIDER_TELEMETRY_RECEIPT_V1]
    coverage = [validate_provider_coverage_revision(value) for value in payloads if value.get("contract_type") == PROVIDER_COVERAGE_REVISION_V1]
    samples = [validate_usage_counter_sample(value) for value in payloads if value.get("contract_type") == USAGE_COUNTER_SAMPLE_V1]
    if len(receipts) != 1 or len(coverage) not in {1, 2} or len(samples) > 1:
        raise CompanyTelemetryIngestError("durable telemetry transaction membership differs")
    receipt = receipts[0]
    lifecycle = [item for item in coverage if item["coverage_surface"] == "lifecycle"]
    usage = [item for item in coverage if item["coverage_surface"] == "usage"]
    if len(lifecycle) != 1 or len(usage) > 1:
        raise CompanyTelemetryIngestError("durable telemetry coverage membership differs")
    return ProviderTelemetryIngestResult(
        receipt_id=receipt["receipt_id"], provider=receipt["provider"],
        parse_outcome=receipt["parse_outcome"], normalized_kind=receipt["normalized_kind"],
        dispatch_join_state=receipt["dispatch_join"]["state"],
        lifecycle_coverage_revision_id=lifecycle[0]["revision_id"],
        usage_coverage_revision_id="" if not usage else usage[0]["revision_id"],
        usage_sample_id=None if not samples else samples[0]["sample_id"],
        transaction_id=receipt["transaction_id"], command_id=receipt["command_id"],
        global_sequence=record.global_sequence, idempotent_replay=idempotent_replay,
    )


def _coverage_result_from_record(
    record: LedgerTransactionRecord, transaction_id: str, command_id: str,
    idempotent_replay: bool,
) -> ProviderCoverageResult:
    values = [validate_provider_coverage_revision(_plain(event.event["payload"])) for event in record.events if _plain(event.event["payload"]).get("contract_type") == PROVIDER_COVERAGE_REVISION_V1]
    if len(values) != 1:
        raise CompanyTelemetryIngestError("coverage transaction membership differs")
    item = values[0]
    return ProviderCoverageResult(item["coverage_scope_id"], item["coverage_surface"], item["revision_id"], item["revision"], item["state"], transaction_id, command_id, record.global_sequence, idempotent_replay)


def _needs_user_blob(state: CompanyStateOwner, text: str, media_type: str) -> dict[str, Any]:
    content_type = "question" if media_type == NEEDS_USER_QUESTION_MEDIA_TYPE else "answer"
    if not isinstance(text, str) or not text.strip():
        raise CompanyNeedsUserError("needs-user content must be nonempty text")
    raw = canonical_company_json_bytes({"schema_version": 1, "content_type": content_type, "text": text})
    if len(raw) > MAX_NEEDS_USER_CONTENT_BYTES:
        raise CompanyNeedsUserError("needs-user content exceeds bound")
    metadata = state.blobs.put(raw)
    return _blob_ref(metadata.sha256, metadata.size_bytes, media_type)


def _needs_user_payload(
    binding: Mapping[str, Any], *, item_id: str, revision: int, previous: str,
    origin_execution_id: str, opened_chief_term: int, state: str,
    question_blob: Mapping[str, Any], answer_blob: Mapping[str, Any] | None,
    created_at: str, updated_at: str, answered_at: str | None,
    answered_by_chief_term: int | None, answer_control_intent_id: str | None,
) -> dict[str, Any]:
    payload = {
        "contract_type": NEEDS_USER_REVISION_V1, "schema_version": 1, **binding,
        "item_id": item_id, "revision_id": _telemetry_id(binding, "needs-user-revision", item_id, str(revision)),
        "revision": revision, "previous_revision_sha256": previous,
        "origin_execution_id": origin_execution_id, "opened_chief_term": opened_chief_term,
        "state": state, "question_sha256": question_blob["sha256"], "question_blob": dict(question_blob),
        "answer_sha256": None if answer_blob is None else answer_blob["sha256"],
        "answer_blob": None if answer_blob is None else dict(answer_blob),
        "created_at": created_at, "updated_at": updated_at, "answered_at": answered_at,
        "answered_by_chief_term": answered_by_chief_term,
        "answer_control_intent_id": answer_control_intent_id,
        "observation": {"state": "known", "reason": "observed"}, "revision_sha256": ZERO_SHA256,
    }
    payload["revision_sha256"] = company_contract_sha256({key: value for key, value in payload.items() if key != "revision_sha256"})
    return validate_needs_user_revision(payload)


def _needs_user_control_intent(
    binding: Mapping[str, Any], *, grant: Mapping[str, Any], execution_id: str,
    control_intent_id: str, command_id: str, receipt_id: str, item_id: str,
    answer_sha256: str, at: str,
) -> dict[str, Any]:
    request = {"operation": "needs_user.answer", "item_id": item_id, "cooperative_user_intent": True}
    result = {"state": "answered", "item_id": item_id, "answer_sha256": answer_sha256}
    receipt = {"receipt_type": "needs_user_answer", "item_id": item_id, "answer_sha256": answer_sha256}
    payload = {
        "contract_type": CONTROL_INTENT_V1, "schema_version": 1, **binding,
        "control_intent_id": control_intent_id, "command_id": command_id,
        "execution_id": execution_id, "authority_grant": dict(grant),
        "authority_grant_sha256": grant["grant_sha256"],
        "request_payload": request, "request_sha256": company_contract_sha256(request),
        "outcome": "committed", "result_payload": result, "result_sha256": company_contract_sha256(result),
        "receipt_id": receipt_id, "terminal_receipt": receipt, "receipt_sha256": company_contract_sha256(receipt),
        "created_at": at, "terminal_at": at, "provenance": "AOI_verified",
        "observation": {"state": "known", "reason": "observed"},
    }
    return validate_control_intent(payload)


def _needs_user_result_from_record(
    record: LedgerTransactionRecord, transaction_id: str, command_id: str,
    idempotent_replay: bool,
) -> NeedsUserResult:
    revisions = [validate_needs_user_revision(_plain(event.event["payload"])) for event in record.events if _plain(event.event["payload"]).get("contract_type") == NEEDS_USER_REVISION_V1]
    if len(revisions) != 1:
        raise CompanyNeedsUserError("needs-user transaction membership differs")
    item = revisions[0]
    if item["state"] == "answered":
        intents = [validate_control_intent(_plain(event.event["payload"])) for event in record.events if _plain(event.event["payload"]).get("contract_type") == CONTROL_INTENT_V1]
        if len(intents) != 1 or intents[0]["control_intent_id"] != item["answer_control_intent_id"]:
            raise CompanyNeedsUserError("needs-user answer control intent differs")
    return NeedsUserResult(item["item_id"], item["revision_id"], item["revision"], item["state"], transaction_id, command_id, record.global_sequence, idempotent_replay)


def _genesis_ids(company_id: str, incarnation: int, generation: int) -> dict[str, str]:
    """Derive bounded IDs without embedding an unbounded company identifier."""

    labels = (
        "supervisor", "supervisor_grant", "chief", "chief_grant", "chief_carrier",
        "chief_node", "chief_execution", "transaction", "command",
        "manifest_event", "supervisor_grant_event", "chief_grant_event",
        "chief_node_event", "chief_term_event", "chief_carrier_event",
        "chief_carrier_execution_event",
        "rtl_lead_node", "dv_lead_node", "pd_lead_node",
        "rtl_department", "dv_department", "pd_department",
        "rtl_lead_node_event", "dv_lead_node_event", "pd_lead_node_event",
        "rtl_identity_event", "dv_identity_event", "pd_identity_event",
        "rtl_snapshot_rev1_event", "dv_snapshot_rev1_event", "pd_snapshot_rev1_event",
    )
    result: dict[str, str] = {}
    for label in labels:
        suffix = company_contract_sha256({
            "company_id": company_id,
            "company_incarnation": incarnation,
            "lock_domain_generation": generation,
            "label": label,
        })[:24]
        result[label] = f"genesis-{label.replace('_', '-')}-{suffix}"
    return result


def _carrier_payload(
    binding: Mapping[str, Any],
    *,
    actor_id: str,
    carrier_id: str,
    bootstrap_at: str,
    known_carrier: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if known_carrier is None:
        return {
            "contract_type": CARRIER_BINDING_V1,
            "schema_version": 1,
            **binding,
            "carrier_id": carrier_id,
            "actor_id": actor_id,
            "provider": "unknown",
            "model": None,
            "session_id": None,
            "session_availability": "unknown",
            "state": "unknown",
            "bound_at": bootstrap_at,
            "last_observed_at": bootstrap_at,
            "observation": {
                "state": "unknown",
                "reason": "provider_session_unavailable",
            },
        }
    fields = {
        "carrier_id", "provider", "model", "session_id", "thread_id",
        "provenance", "observation",
    }
    if set(known_carrier) != fields:
        raise CompanySupervisorError("known carrier bootstrap input is incomplete")
    payload = {
        "contract_type": CARRIER_BINDING_V1,
        "schema_version": 1,
        **binding,
        "carrier_id": known_carrier["carrier_id"],
        "actor_id": actor_id,
        "provider": known_carrier["provider"],
        "model": known_carrier["model"],
        "session_id": known_carrier["session_id"],
        "session_availability": "available",
        "state": "active",
        "bound_at": bootstrap_at,
        "last_observed_at": bootstrap_at,
        "observation": known_carrier["observation"],
    }
    try:
        result = validate_carrier_binding(payload)
    except ValueError as exc:
        raise CompanySupervisorError("known carrier bootstrap input is invalid") from exc
    if (
        result["observation"]["state"] != "known"
        or known_carrier["provenance"] != "agent_reported"
    ):
        raise CompanySupervisorError(
            "known carrier bootstrap provenance must be agent_reported",
        )
    if not isinstance(known_carrier["thread_id"], str) or not known_carrier["thread_id"]:
        raise CompanySupervisorError("known carrier bootstrap input lacks a thread ID")
    return result


def _carrier_provenance(known_carrier: Mapping[str, Any] | None) -> str:
    return "unknown" if known_carrier is None else str(known_carrier["provenance"])


def _organization_node(
    binding: Mapping[str, Any],
    *,
    node_id: str,
    department_id: str | None,
    parent_node_id: str | None,
    role: str,
    reports_to_node_id: str | None,
    delegation_depth: int,
    status: str = "active",
    bootstrap_at: str,
) -> dict[str, Any]:
    return {
        "contract_type": ORGANIZATION_NODE_V1,
        "schema_version": 1,
        **binding,
        "node_id": node_id,
        "department_id": department_id,
        "parent_node_id": parent_node_id,
        "role": role,
        "reports_to_node_id": reports_to_node_id,
        "can_delegate": True,
        "delegation_depth": delegation_depth,
        "status": status,
        "visibility": "company" if parent_node_id is None else "subtree",
        "created_at": bootstrap_at,
        "observation": {"state": "known", "reason": "observed"},
    }


def _department_identity(
    binding: Mapping[str, Any],
    *,
    department: str,
    department_id: str,
    lead_node_id: str,
    bootstrap_at: str,
) -> dict[str, Any]:
    charter = company_contract_sha256({"department": department, "kind": "charter"})
    scope = company_contract_sha256({"department": department, "kind": "scope"})
    return {
        "contract_type": DEPARTMENT_IDENTITY_V1,
        "schema_version": 1,
        **binding,
        "department_id": department_id,
        "name": department.upper(),
        "charter_sha256": charter,
        "scope_sha256": scope,
        "lead_node_id": lead_node_id,
        "created_at": bootstrap_at,
        "status": "parked",
        "observation": {"state": "known", "reason": "observed"},
    }


def _department_snapshot(
    binding: Mapping[str, Any],
    *,
    department: str,
    department_id: str,
    lead_node_id: str,
    bootstrap_at: str,
) -> dict[str, Any]:
    snapshot, _document, _resources = (
        _genesis_department_snapshot_material(
            binding,
            department=department,
            department_id=department_id,
            lead_node_id=lead_node_id,
            bootstrap_at=bootstrap_at,
        )
    )
    return snapshot


def _genesis_department_snapshot_material(
    binding: Mapping[str, Any],
    *,
    department: str,
    department_id: str,
    lead_node_id: str,
    bootstrap_at: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    tuple[tuple[dict[str, Any], bytes], ...],
]:
    reference_kinds = {
        "charter_ref": "charter",
        "constraints_ref": "constraints",
        "decisions_ref": "decisions",
        "dissent_ref": "dissent",
        "open_questions_ref": "open_questions",
        "blockers_ref": "blockers",
        "risks_ref": "risks",
        "backlog_ref": "backlog",
        "handoff_ref": "handoff",
    }
    resources: list[tuple[dict[str, Any], bytes]] = []
    references: dict[str, dict[str, Any]] = {}
    for field, kind in reference_kinds.items():
        raw = canonical_company_json_bytes({
            "department": department,
            "kind": kind,
        })
        reference = {
            "contract_type": BLOB_REF_V1,
            "schema_version": 1,
            "sha256": _department_digest(department, kind),
            "size_bytes": len(raw),
            "media_type": "application/json",
            "availability": "available",
        }
        references[field] = reference
        resources.append((reference, raw))
    snapshot_id = f"{department_id}-snapshot-rev1"
    document = validate_department_snapshot_document({
        "document_type": "department_snapshot_document_v1",
        "schema_version": 1,
        **dict(binding),
        "department_id": department_id,
        "lead_node_id": lead_node_id,
        "snapshot_id": snapshot_id,
        "revision": 1,
        "previous_snapshot_id": None,
        "previous_document_sha256": None,
        "company_cursor": 1,
        "captured_at": bootstrap_at,
        "capture_reason": "genesis",
        **references,
        "active_dispatch_request_ids": [],
        "active_execution_ids": [],
        "job_ids": [],
        "evidence_ids": [],
        "artifact_refs": [],
    })
    raw_document = canonical_company_json_bytes(document)
    document_ref = {
        "contract_type": BLOB_REF_V1,
        "schema_version": 1,
        "sha256": company_contract_sha256(document),
        "size_bytes": len(raw_document),
        "media_type": DEPARTMENT_SNAPSHOT_MEDIA_TYPE,
        "availability": "available",
    }
    resources.append((document_ref, raw_document))
    snapshot = {
        "contract_type": DEPARTMENT_SNAPSHOT_V1,
        "schema_version": 1,
        **binding,
        "snapshot_id": snapshot_id,
        "department_id": department_id,
        "revision": 1,
        "company_cursor": 1,
        "previous_snapshot_id": None,
        "charter_sha256": _department_digest(department, "charter"),
        "constraints_sha256": _department_digest(department, "constraints"),
        "decisions_sha256": _department_digest(department, "decisions"),
        "open_questions_sha256": _department_digest(department, "open_questions"),
        "handoff_sha256": _department_digest(department, "handoff"),
        "artifact_refs": [document_ref],
        "captured_at": bootstrap_at,
        "observation": {"state": "known", "reason": "observed"},
    }
    return snapshot, document, tuple(resources)


def _department_digest(department: str, kind: str) -> str:
    return company_contract_sha256({"department": department, "kind": kind})


def _chief_execution_node(
    binding: Mapping[str, Any],
    *,
    execution_id: str,
    chief_node_id: str,
    carrier: Mapping[str, Any],
    thread_id: str,
    provenance: str,
    bootstrap_at: str,
    engineering_status: str = "active",
    phase: str = "bootstrap",
    wait_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "contract_type": EXECUTION_NODE_V1,
        "schema_version": 1,
        **binding,
        "execution_id": execution_id,
        "execution_kind": "carrier",
        "display_name": "Chief carrier",
        "organization_node_id": chief_node_id,
        "department_id": None,
        "parent_execution_id": None,
        "execution_depth": 0,
        "execution_path": [execution_id],
        "task_id": None,
        "packet_id": None,
        "thread_id": thread_id,
        "turn_id": None,
        "agent_id": None,
        "job_id": None,
        "dispatch_id": None,
        "registration_id": None,
        "receipt_id": None,
        "provider": carrier["provider"],
        "model": carrier["model"],
        "effort": None,
        "carrier_id": carrier["carrier_id"],
        "role": "chief",
        "delegation_depth": 0,
        "engineering_status": engineering_status,
        "runtime_status": "running",
        "attention_overlays": [],
        "objective": "Operate the company",
        "phase": phase,
        "created_at": bootstrap_at,
        "updated_at": bootstrap_at,
        "last_event_at": bootstrap_at,
        "heartbeat_at": bootstrap_at,
        "wait_reason": wait_reason,
        "current_tool": None,
        "terminal_at": None,
        "usage_cursor": 0,
        "job_ids": [],
        "evidence_ids": [],
        "provenance": provenance,
        "observation": carrier["observation"],
    }


__all__ = [
    "ChiefTakeoverResult",
    "CompanyChiefTakeoverError",
    "CompanyDepartmentDispatchCapacityBlocked",
    "CompanyDepartmentLifecycleError",
    "CompanyExecutionRegistrationError",
    "CompanyExternalJobError",
    "CompanyNeedsUserError",
    "CompanySupervisor",
    "CompanySupervisorDashboardRefreshError",
    "CompanySupervisorError",
    "CompanyTelemetryIngestError",
    "CompanyWorkDefinitionError",
    "DepartmentDispatchResult",
    "DepartmentExecutionStatusResult",
    "DepartmentLifecycleResult",
    "ExecutionRuntimeStatusResult",
    "ExternalJobLifecycleResult",
    "NeedsUserResult",
    "ProviderCoverageResult",
    "ProviderTelemetryIngestResult",
    "WorkDefinitionEnforcementResult",
    "WorkDefinitionRegistrationResult",
]
