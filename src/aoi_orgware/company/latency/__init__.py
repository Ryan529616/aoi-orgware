"""Pure, off-ledger latency-observation contracts."""

from .acceptance_contract import (
    EngineeringAcceptanceCandidateReceiptV1,
    build_engineering_acceptance_candidate,
    validate_engineering_acceptance_candidate_against_witness,
    validate_engineering_acceptance_candidate_receipt,
)
from .stage_spans import (
    SupervisorStageMarkV1,
    SupervisorStageSpanV1,
    build_dispatch_accepted_mark,
    build_engineering_acceptance_candidate_receipt_sealed_mark,
    derive_stage_span,
)

__all__ = (
    "EngineeringAcceptanceCandidateReceiptV1",
    "SupervisorStageMarkV1",
    "SupervisorStageSpanV1",
    "build_dispatch_accepted_mark",
    "build_engineering_acceptance_candidate",
    "build_engineering_acceptance_candidate_receipt_sealed_mark",
    "derive_stage_span",
    "validate_engineering_acceptance_candidate_against_witness",
    "validate_engineering_acceptance_candidate_receipt",
)
