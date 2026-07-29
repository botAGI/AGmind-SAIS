"""Offline authenticated evidence verification and projection rebuild CLI."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import NoReturn

from agmind_immune.evidence.projection import ProjectionStore, RebuildReport
from agmind_immune.evidence.segments import SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal, AckJournalSnapshot
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
)
from agmind_immune.ingest.service import AcceptanceCoordinator

_DEFAULT_TRUST_ROOT = Path("/etc/agmind-sais/observer-trust-root.json")
_DEFAULT_PUBLIC_KEYS = Path(
    "/var/lib/agmind-sais/observer/observer-public-keys.json"
)
_MAX_PUBLIC_KEYS_BYTES = 64 * 1024


def _bounded_regular_file(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > limit
        ):
            raise ValueError(f"unsafe replay input: {path}")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise ValueError(f"replay input exceeds its bound: {path}")
        return raw
    finally:
        os.close(descriptor)


def _verifier() -> EnvelopeVerifier:
    trust_path = Path(
        os.environ.get("AGMIND_OBSERVER_TRUST_ROOT_FILE", _DEFAULT_TRUST_ROOT)
    )
    metadata_path = Path(
        os.environ.get("AGMIND_OBSERVER_PUBLIC_KEYS_FILE", _DEFAULT_PUBLIC_KEYS)
    )
    root = PinnedObserverRoot.load(trust_path)
    metadata = _bounded_regular_file(metadata_path, _MAX_PUBLIC_KEYS_BYTES)
    return EnvelopeVerifier(root, AnchoredPublicKeyChain.from_value(root, metadata))


def _open_authorities(
    evidence_dir: Path,
) -> tuple[AcceptanceCoordinator, SegmentStore, AckJournal]:
    store = SegmentStore(evidence_dir)
    try:
        coordinator = AcceptanceCoordinator.open_and_recover(_verifier(), store)
        journal = AckJournal.open_and_recover(store)
    except BaseException:
        store.close(flush=False)
        raise
    return coordinator, store, journal


def verify_evidence(evidence_dir: Path) -> AckJournalSnapshot:
    """Reverify every segment and recover the bound ACK journal without mutation."""
    _coordinator, store, journal = _open_authorities(evidence_dir)
    try:
        snapshot = journal.snapshot()
        tuple(store.iter_authenticated_records(after=0, through=store.acceptance_cursor))
        return snapshot
    finally:
        journal.close()
        store.close(flush=False)


def rebuild_projection(evidence_dir: Path, projection_db: Path) -> RebuildReport:
    """Rebuild one SQLite cache from the frozen authenticated ACK prefix."""
    _coordinator, store, journal = _open_authorities(evidence_dir)
    projection: ProjectionStore | None = None
    try:
        projection = ProjectionStore.open(
            projection_db,
            evidence=store,
            acknowledgements=journal,
        )
        return projection.rebuild()
    finally:
        if projection is not None:
            projection.close()
        journal.close()
        store.close(flush=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m agmind_immune.replay")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("evidence_dir", type=Path)
    rebuild = commands.add_parser("rebuild")
    rebuild.add_argument("evidence_dir", type=Path)
    rebuild.add_argument("projection_db", type=Path)
    return parser


def _fatal(parser: argparse.ArgumentParser, error: BaseException) -> NoReturn:
    parser.exit(1, f"replay failed: {error}\n")


def main() -> None:
    parser = _parser()
    arguments = parser.parse_args()
    output: dict[str, object]
    try:
        if arguments.command == "verify":
            snapshot = verify_evidence(arguments.evidence_dir)
            output = {
                "healthy": snapshot.healthy,
                "confirmed_through": snapshot.confirmed_through,
            }
        else:
            report = rebuild_projection(
                arguments.evidence_dir,
                arguments.projection_db,
            )
            output = {
                "snapshot_hash": report.snapshot_hash,
                "table_counts": dict(report.table_counts),
                "source_record_count": report.source_record_count,
                "duplicate_count": report.duplicate_count,
                "cursor": (
                    None
                    if report.cursor is None
                    else {
                        "host_id": report.cursor.host_id,
                        "source_sequence": report.cursor.source_sequence,
                        "event_id": report.cursor.event_id,
                        "content_sha256": report.cursor.content_sha256,
                        "frame_sha256": report.cursor.frame_sha256,
                    }
                ),
            }
    except Exception as error:  # noqa: BLE001 - CLI converts all operational failures
        _fatal(parser, error)
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
