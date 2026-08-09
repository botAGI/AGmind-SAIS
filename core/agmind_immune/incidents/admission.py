"""Opaque, one-use candidate admission authority and public observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Never, SupportsIndex, final

from agmind_immune.coverage import MutationReadiness
from agmind_immune.evidence.projection import ProjectionCursor
from agmind_immune.evidence.segments import EvidenceRef
from agmind_immune.incidents.models import ContainmentCandidateV1

_VIEW_FACTORY = object()


class CandidateAdmissionError(RuntimeError):
    """A candidate cannot be admitted from the current live authority."""


@dataclass(frozen=True, slots=True)
class CandidateStatusObservation:
    """Non-authoritative candidate status suitable only for observation."""

    candidate: ContainmentCandidateV1
    invalidation_event_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.candidate) is not ContainmentCandidateV1
            or type(self.invalidation_event_ids) is not tuple
            or any(type(value) is not str for value in self.invalidation_event_ids)
        ):
            raise TypeError("candidate status observation fields are not exact")


@final
class CandidateAdmissionView:
    """Factory-issued local authority consumed only by its issuing controller."""

    __slots__ = (
        "_admission_rebuild_epoch",
        "_authority_revision",
        "_authority_snapshot_event_id",
        "_candidate",
        "_candidate_facts_sha256",
        "_controller_lifecycle",
        "_evidence_lifecycle",
        "_nonce",
        "_projection_cursor",
        "_projection_lifecycle",
        "_readiness",
        "_terminal_ref",
    )

    _admission_rebuild_epoch: int
    _authority_revision: int
    _authority_snapshot_event_id: str
    _candidate: ContainmentCandidateV1
    _candidate_facts_sha256: str
    _controller_lifecycle: object
    _evidence_lifecycle: object
    _nonce: object
    _projection_cursor: ProjectionCursor
    _projection_lifecycle: object
    _readiness: MutationReadiness
    _terminal_ref: EvidenceRef

    def __init__(
        self,
        *,
        candidate: ContainmentCandidateV1,
        candidate_facts_sha256: str,
        authority_snapshot_event_id: str,
        projection_cursor: ProjectionCursor,
        terminal_ref: EvidenceRef,
        admission_rebuild_epoch: int,
        authority_revision: int,
        readiness: MutationReadiness,
        controller_lifecycle: object,
        projection_lifecycle: object,
        evidence_lifecycle: object,
        nonce: object,
        _factory: object,
    ) -> None:
        if _factory is not _VIEW_FACTORY:
            raise TypeError("candidate admission views are factory-issued")
        object.__setattr__(self, "_candidate", candidate)
        object.__setattr__(self, "_candidate_facts_sha256", candidate_facts_sha256)
        object.__setattr__(
            self,
            "_authority_snapshot_event_id",
            authority_snapshot_event_id,
        )
        object.__setattr__(self, "_projection_cursor", projection_cursor)
        object.__setattr__(self, "_terminal_ref", terminal_ref)
        object.__setattr__(
            self,
            "_admission_rebuild_epoch",
            admission_rebuild_epoch,
        )
        object.__setattr__(self, "_authority_revision", authority_revision)
        object.__setattr__(self, "_readiness", readiness)
        object.__setattr__(self, "_controller_lifecycle", controller_lifecycle)
        object.__setattr__(self, "_projection_lifecycle", projection_lifecycle)
        object.__setattr__(self, "_evidence_lifecycle", evidence_lifecycle)
        object.__setattr__(self, "_nonce", nonce)

    @property
    def candidate(self) -> ContainmentCandidateV1:
        return self._candidate

    @property
    def candidate_facts_sha256(self) -> str:
        return self._candidate_facts_sha256

    @property
    def authority_snapshot_event_id(self) -> str:
        return self._authority_snapshot_event_id

    @property
    def projection_cursor(self) -> ProjectionCursor:
        return self._projection_cursor

    @property
    def terminal_ref(self) -> EvidenceRef:
        return self._terminal_ref

    @property
    def admission_rebuild_epoch(self) -> int:
        return self._admission_rebuild_epoch

    @property
    def authority_revision(self) -> int:
        return self._authority_revision

    @property
    def readiness(self) -> MutationReadiness:
        return self._readiness

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("candidate admission views are immutable")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CandidateAdmissionView is final")

    def __copy__(self) -> Never:
        raise CandidateAdmissionError("candidate admission views cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        del memo
        raise CandidateAdmissionError("candidate admission views cannot be copied")

    def __reduce__(self) -> Never:
        raise CandidateAdmissionError("candidate admission views cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise CandidateAdmissionError("candidate admission views cannot be serialized")


def _issue_candidate_admission_view(
    *,
    candidate: ContainmentCandidateV1,
    candidate_facts_sha256: str,
    authority_snapshot_event_id: str,
    projection_cursor: ProjectionCursor,
    terminal_ref: EvidenceRef,
    admission_rebuild_epoch: int,
    authority_revision: int,
    readiness: MutationReadiness,
    controller_lifecycle: object,
    projection_lifecycle: object,
    evidence_lifecycle: object,
    nonce: object,
) -> CandidateAdmissionView:
    return CandidateAdmissionView(
        candidate=candidate,
        candidate_facts_sha256=candidate_facts_sha256,
        authority_snapshot_event_id=authority_snapshot_event_id,
        projection_cursor=projection_cursor,
        terminal_ref=terminal_ref,
        admission_rebuild_epoch=admission_rebuild_epoch,
        authority_revision=authority_revision,
        readiness=readiness,
        controller_lifecycle=controller_lifecycle,
        projection_lifecycle=projection_lifecycle,
        evidence_lifecycle=evidence_lifecycle,
        nonce=nonce,
        _factory=_VIEW_FACTORY,
    )


__all__ = [
    "CandidateAdmissionError",
    "CandidateAdmissionView",
    "CandidateStatusObservation",
]
