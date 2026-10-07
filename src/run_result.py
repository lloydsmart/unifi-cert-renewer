"""Version 1 structured result for one UniFi CLI invocation."""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4


class Outcome(StrEnum):
    SUCCESS_CHANGED = "success_changed"
    SUCCESS_NO_CHANGE = "success_no_change"
    SUCCESS_PREPARED = "success_prepared"
    ATTENTION_DUE = "attention_due"
    FAILURE_PRE_ATTEMPT = "failure_pre_attempt"
    FAILURE_PARTIAL = "failure_partial"
    FAILURE_AMBIGUOUS = "failure_ambiguous"


class Operation(StrEnum):
    INSPECT = "inspect"
    RENEW_DUE = "renew_due"
    RENEW_NOW = "renew_now"
    GENERATE_CSR = "generate_csr"
    RETRIEVE_CSR = "retrieve_csr"
    SIGN_CSR = "sign_csr"
    INSTALL = "install"


class Stage(StrEnum):
    STARTUP = "startup"
    CONFIGURATION = "configuration"
    LOCK = "lock"
    INSPECTION = "inspection"
    DECISION = "decision"
    PREFLIGHT = "preflight"
    CSR_GENERATION = "csr_generation"
    CSR_RETRIEVAL = "csr_retrieval"
    SIGNING = "signing"
    ISSUED_VALIDATION = "issued_validation"
    INSTALLATION = "installation"
    ACTIVATION = "activation"
    LIVE_VERIFICATION = "live_verification"
    FINALIZATION = "finalization"
    COMPLETED = "completed"


class Milestone(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    NOT_APPLICABLE = "not_applicable"


class Change(StrEnum):
    NONE = "none"
    CONFIRMED = "confirmed"
    POSSIBLE = "possible"


class Reason(StrEnum):
    CONFIG_INVALID = "config_invalid"
    LOCK_BUSY = "lock_busy"
    LOCK_FAILED = "lock_failed"
    PENDING_STATE = "pending_state"
    INSPECTION_FAILED = "inspection_failed"
    CSR_FAILED = "csr_failed"
    SIGNING_FAILED = "signing_failed"
    VALIDATION_FAILED = "validation_failed"
    INSTALLATION_FAILED = "installation_failed"
    VERIFICATION_FAILED = "verification_failed"
    RECOVERY_REQUIRED = "recovery_required"
    UNEXPECTED_FAILURE = "unexpected_failure"


MILESTONE_NAMES = ("csr", "issuance", "installation", "activation", "live_tls")
_SEVERITY = {
    Outcome.SUCCESS_NO_CHANGE: 0,
    Outcome.SUCCESS_PREPARED: 1,
    Outcome.SUCCESS_CHANGED: 2,
    Outcome.ATTENTION_DUE: 3,
    Outcome.FAILURE_PRE_ATTEMPT: 4,
    Outcome.FAILURE_PARTIAL: 5,
    Outcome.FAILURE_AMBIGUOUS: 6,
}


def utc_now():
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class TargetResult:
    target: str
    outcome: Outcome = Outcome.FAILURE_PRE_ATTEMPT
    stage: Stage = Stage.STARTUP
    renewal_due: bool | None = None
    change: Change = Change.NONE
    manual_recovery_required: bool = False
    reason_code: Reason | None = None
    message: str = "Operation has not completed."
    certificate: dict[str, str | None] | None = None
    milestones: dict[str, Milestone] = field(
        default_factory=lambda: {
            name: Milestone.NOT_ATTEMPTED for name in MILESTONE_NAMES
        }
    )

    def as_dict(self):
        return {
            "target": self.target,
            "outcome": self.outcome.value,
            "stage": self.stage.value,
            "renewal_due": self.renewal_due,
            "change": self.change.value,
            "manual_recovery_required": self.manual_recovery_required,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "message": self.message,
            "certificate": self.certificate,
            "milestones": {key: value.value for key, value in self.milestones.items()},
        }


@dataclass
class RunResult:
    operation: Operation
    attempt_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    outcome: Outcome = Outcome.FAILURE_PRE_ATTEMPT
    stage: Stage = Stage.STARTUP
    manual_recovery_required: bool = False
    reason_code: Reason | None = None
    message: str = "Operation has not completed."
    results: list[TargetResult] = field(default_factory=list)

    def finish(self):
        if self.results:
            chosen = max(self.results, key=lambda item: _SEVERITY[item.outcome])
            self.outcome = chosen.outcome
            self.stage = (
                chosen.stage
                if _SEVERITY[chosen.outcome] >= _SEVERITY[Outcome.ATTENTION_DUE]
                else Stage.COMPLETED
            )
            self.reason_code = chosen.reason_code
            self.message = chosen.message
            self.manual_recovery_required |= any(
                item.manual_recovery_required for item in self.results
            )
        self.finished_at = utc_now()

    def as_dict(self):
        return {
            "schema_version": 1,
            "product": "unifi",
            "operation": self.operation.value,
            "attempt_id": self.attempt_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcome": self.outcome.value,
            "stage": self.stage.value,
            "manual_recovery_required": self.manual_recovery_required,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "message": self.message,
            "results": [item.as_dict() for item in self.results],
        }

    def to_json(self):
        return json.dumps(self.as_dict(), ensure_ascii=True, allow_nan=False)


_FAILURE_REASONS = {
    Stage.CONFIGURATION: Reason.CONFIG_INVALID,
    Stage.LOCK: Reason.LOCK_FAILED,
    Stage.INSPECTION: Reason.INSPECTION_FAILED,
    Stage.DECISION: Reason.VALIDATION_FAILED,
    Stage.PREFLIGHT: Reason.VALIDATION_FAILED,
    Stage.CSR_GENERATION: Reason.CSR_FAILED,
    Stage.CSR_RETRIEVAL: Reason.CSR_FAILED,
    Stage.SIGNING: Reason.SIGNING_FAILED,
    Stage.ISSUED_VALIDATION: Reason.VALIDATION_FAILED,
    Stage.INSTALLATION: Reason.INSTALLATION_FAILED,
    Stage.ACTIVATION: Reason.VERIFICATION_FAILED,
    Stage.LIVE_VERIFICATION: Reason.VERIFICATION_FAILED,
    Stage.FINALIZATION: Reason.RECOVERY_REQUIRED,
}


class RunEvidence:
    """Worker-observed progress for one invocation, without privileged journal access."""

    def __init__(self, operation: Operation | str):
        self.run = RunResult(Operation(operation))
        self.target = TargetResult("unifi")
        self.run.results.append(self.target)
        self.stage = Stage.STARTUP
        self.certificate = None

    def confirm(self, name: str) -> None:
        self.target.milestones[name] = Milestone.CONFIRMED
        if name == "issuance":
            self.target.change = Change.CONFIRMED

    def signing_dispatch(self) -> None:
        self.target.milestones["issuance"] = Milestone.UNCERTAIN
        self.target.change = Change.POSSIBLE

    def executor_dispatch(self, operation: str) -> None:
        if operation == "install":
            self.target.milestones["installation"] = Milestone.UNCERTAIN
        elif operation == "verify_pending":
            self.target.milestones["activation"] = Milestone.UNCERTAIN
            self.target.milestones["live_tls"] = Milestone.UNCERTAIN

    def success(self, outcome: Outcome, message: str, *, renewal_due=None) -> None:
        self.target.outcome = outcome
        self.target.stage = (
            Stage(self.stage) if outcome is Outcome.ATTENTION_DUE else Stage.COMPLETED
        )
        self.target.renewal_due = renewal_due
        self.target.reason_code = None
        self.target.message = message
        if self.certificate is not None:
            self.target.certificate = {
                "fingerprint_sha256": self.certificate.certificate_sha256,
                "expiry_date": self.certificate.not_valid_after.date().isoformat(),
            }

    def failure(self, *, reason: Reason | None = None) -> None:
        stage = Stage(self.stage)
        self.target.stage = stage
        self.target.reason_code = reason or _FAILURE_REASONS.get(
            stage, Reason.UNEXPECTED_FAILURE
        )
        uncertain = any(
            value is Milestone.UNCERTAIN for value in self.target.milestones.values()
        )
        if uncertain:
            self.target.outcome = Outcome.FAILURE_AMBIGUOUS
        elif self.target.change is Change.CONFIRMED:
            self.target.outcome = Outcome.FAILURE_PARTIAL
        else:
            self.target.outcome = Outcome.FAILURE_PRE_ATTEMPT
        self.target.manual_recovery_required = (
            self.target.change is not Change.NONE or uncertain
        )
        self.target.message = "Renewer stopped; inspect the current state before retry."
        if stage == Stage.CSR_GENERATION:
            self.target.milestones["csr"] = Milestone.FAILED
        if self.certificate is not None:
            self.target.certificate = {
                "fingerprint_sha256": self.certificate.certificate_sha256,
                "expiry_date": self.certificate.not_valid_after.date().isoformat(),
            }

    def finish(self) -> str:
        self.run.finish()
        return self.run.to_json()
