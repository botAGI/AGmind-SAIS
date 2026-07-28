"""Minimal Phase-5B append-before-commit acceptance coordinator."""

from __future__ import annotations

from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    SegmentStore,
)
from agmind_immune.ingest.envelope import (
    CoreEventV1,
    EnvelopeConflict,
    EnvelopeVerifier,
)

_COORDINATOR_FACTORY = object()


class AcceptanceCoordinator:
    """Durably append a staged envelope before committing verifier/FSM state."""

    def __init__(
        self,
        verifier: EnvelopeVerifier,
        segment_store: SegmentStore,
        *,
        _factory: object,
    ) -> None:
        if _factory is not _COORDINATOR_FACTORY:
            raise TypeError(
                "use AcceptanceCoordinator.create_empty() or open_and_recover()"
            )
        self.verifier = verifier
        self.segment_store = segment_store

    def accept(self, item: CoreEventV1) -> EvidenceRef:
        try:
            verified = self.verifier.verify(
                item.envelope,
                sequence=item.sequence,
                event_id=item.event_id,
                content_sha256=item.content_sha256,
            )
        except EnvelopeConflict:
            self.segment_store.enter_read_only("evidence_conflict")
            self.verifier._enter_read_only_after_durable_fence()
            raise
        return self.segment_store.append(
            verified,
            EvidencePriority(verified.evidence_priority),
        )

    @classmethod
    def create_empty(
        cls,
        verifier: EnvelopeVerifier,
        segment_store: SegmentStore,
    ) -> AcceptanceCoordinator:
        """Bind a verifier only when the locked evidence lifecycle is pristine."""
        segment_store._bind_empty(verifier)
        return cls(verifier, segment_store, _factory=_COORDINATOR_FACTORY)

    @classmethod
    def open_and_recover(
        cls,
        verifier: EnvelopeVerifier,
        segment_store: SegmentStore,
    ) -> AcceptanceCoordinator:
        """Rebuild verifier authority from every reverified AGF1 record."""
        segment_store._bind_and_recover(verifier)
        return cls(verifier, segment_store, _factory=_COORDINATOR_FACTORY)

    recover = open_and_recover
