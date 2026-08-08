from __future__ import annotations

import hashlib
import importlib
import os
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from agmind_immune.canonicaljson import (
    candidate_facts_sha256,
    canonical_json,
)
from agmind_immune.canonicaljson import (
    candidate_id as derive_candidate_id,
)
from agmind_immune.canonicaljson import (
    incident_id as derive_incident_id,
)
from agmind_immune.contracts import EventEnvelopeV1
from agmind_immune.evidence.dedup import _logical_primary_identity_v2
from agmind_immune.evidence.segments import (
    EvidencePriority,
    EvidenceRef,
    StoredEvidenceRecord,
)
from agmind_immune.incidents.models import ContainmentCandidateV1, IncidentV1
from tests.phase5b_helpers import BOOT_A, envelope_value, private_key

PRIMARY_EVENT_ID = "evt_" + "a" * 64
SNAPSHOT_EVENT_ID = "evt_" + "b" * 64
INCIDENT_ID = "inc_b6a20642d932fed5b59e1d7221f7dacc8824a244fce8fcd85f5139b837ba5f52"
CONTAINER_ID = "f" * 64
DETECTOR_BUNDLE_SHA256 = "f6189db90ea61fefe991672b20316f1693f723de28ab37800029a40545af7b15"
CANDIDATE_ID = "cand_e2a860ac90463466aa8052b923eb0a8887a566173603a56837050eb9e3030cbd"
MODEL_HOST_ID = "11111111-1111-4111-8111-111111111111"
MODEL_BOOT_ID = "22222222-2222-4222-8222-222222222222"
STARTED_AT = "2026-07-27T12:00:00Z"
RULE = "AGmind PCC Suspicious Process Outbound Connect"
RULE_VERSION = "agmind-pcc-rules-v1"


def _subject() -> Any:
    try:
        return importlib.import_module("agmind_immune.evidence.projection_v2")
    except ModuleNotFoundError:
        pytest.fail("dormant Projection V2 slice is not implemented")


def _record(*, boot_id: str = BOOT_A) -> StoredEvidenceRecord:
    value = envelope_value(private_key(11), sequence=1, boot_id=boot_id)
    encoded = canonical_json(value)
    return StoredEvidenceRecord(
        envelope=value,
        canonical_envelope=encoded,
        priority=EvidencePriority.ROUTINE,
        accepted_at="2026-07-28T10:00:00Z",
        ref=EvidenceRef(
            segment_id="523e4567-e89b-42d3-a456-426614174000",
            segment_relative_path=(
                "segments/2026-07-28/"
                "00000000000000000001-523e4567-e89b-42d3-a456-426614174000.agseg"
            ),
            frame_offset=0,
            frame_size=len(encoded) + 76,
            frame_sha256="f" * 64,
            event_id=str(value["event_id"]),
            source_sequence=1,
            content_sha256=hashlib.sha256(encoded).hexdigest(),
        ),
    )


class _StringSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


def _schema_objects(connection: sqlite3.Connection) -> dict[str, str]:
    return {
        str(row[0]): str(row[1])
        for row in connection.execute(
            "SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name"
        )
    }


def _projection_image_artifacts(path: Path) -> dict[str, tuple[tuple[int, ...], bytes]]:
    artifacts: dict[str, tuple[tuple[int, ...], bytes]] = {}
    for candidate in (
        path,
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
        Path(f"{path}-journal"),
    ):
        try:
            info = candidate.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        artifacts[candidate.name] = (
            (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_nlink,
                info.st_uid,
                info.st_gid,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            ),
            candidate.read_bytes(),
        )
    return artifacts


def _create_projection_image(
    active: Any,
    subject: Any,
    path: Path,
    image: str,
) -> None:
    if image == "absent":
        return
    if image == "zero-length":
        path.touch(mode=0o600)
        path.chmod(0o600)
        return
    if image.startswith("v1"):
        connection = active._connect(path)
        try:
            active._create_schema(connection)
        finally:
            connection.close()
    else:
        connection = subject._v2_connection_for_test(path)
        connection.close()
    path.chmod(0o600)
    if image == "v1-altered-view":
        connection = active._connect(path)
        try:
            connection.execute("CREATE VIEW altered_projection AS SELECT key FROM schema_meta")
        finally:
            connection.close()
    elif image == "v2-altered-index":
        connection = subject._v2_connection_for_test(path)
        try:
            connection.execute("DROP INDEX candidate_invalidations_candidate")
            connection.execute(
                "CREATE INDEX candidate_invalidations_candidate "
                "ON candidate_invalidations(coverage_source_sequence)"
            )
        finally:
            connection.close()


def _persist_hostile_row(
    subject: Any,
    table: str,
    columns: tuple[str, ...],
    values: tuple[object, ...],
) -> tuple[sqlite3.Connection, sqlite3.Row]:
    connection = subject._v2_connection_for_test()
    connection.execute("PRAGMA foreign_keys=OFF")
    connection.execute("PRAGMA ignore_check_constraints=ON")
    placeholders = ",".join("?" for _ in values)
    connection.execute(
        f"INSERT INTO {table}({','.join(columns)}) VALUES({placeholders})",
        values,
    )
    row = connection.execute(
        f"SELECT {','.join(columns)} FROM {table}"
    ).fetchone()
    assert isinstance(row, sqlite3.Row)
    return connection, row


def _incident(*, direct: bool = False) -> IncidentV1:
    value: dict[str, object] = {
        "schema_version": "agmind.incident.v1",
        "incident_id": INCIDENT_ID,
        "primary_event_id": PRIMARY_EVENT_ID,
        "primary_source_sequence": 7,
        "host_id": MODEL_HOST_ID,
        "boot_id": MODEL_BOOT_ID,
        "detector_rule": RULE,
        "detector_rule_version": RULE_VERSION,
        "event_time": "2026-07-27T12:00:00.000000001Z",
        "ingest_time": "2026-07-27T12:00:00.000000002Z",
        "successful_connect": True,
        "investigation_only": direct,
        "missing_required_fields": (),
        "coverage_flags": (),
        "evidence_ids": (PRIMARY_EVENT_ID,) if direct else (PRIMARY_EVENT_ID, SNAPSHOT_EVENT_ID),
        "reason_codes": ("investigation_only",) if direct else (),
        "authority_event_id": PRIMARY_EVENT_ID if direct else SNAPSHOT_EVENT_ID,
    }
    if not direct:
        value.update(
            {
                "docker_container_id": CONTAINER_ID,
                "docker_started_at": STARTED_AT,
                "proc_name": "curl",
                "proc_exe_path": "/usr/bin/curl",
                "proc_parent_name": "sh",
                "destination_ipv4": "1.1.1.1",
                "destination_port": 443,
                "l4_protocol": "tcp",
            }
        )
    return IncidentV1.model_validate(value, strict=True)


def _candidate() -> ContainmentCandidateV1:
    return ContainmentCandidateV1.model_validate(
        {
            "schema_version": "agmind.containment-candidate.v1",
            "candidate_id": CANDIDATE_ID,
            "incident_id": INCIDENT_ID,
            "host_id": MODEL_HOST_ID,
            "boot_id": MODEL_BOOT_ID,
            "primary_event_id": PRIMARY_EVENT_ID,
            "primary_source_sequence": 7,
            "correlation_snapshot_event_id": SNAPSHOT_EVENT_ID,
            "docker_container_id": CONTAINER_ID,
            "docker_started_at": STARTED_AT,
            "image_id": "sha256:" + "e" * 64,
            "repo_digests": ("registry.example/agmind@sha256:" + "d" * 64,),
            "immutable_spec_sha256": "c" * 64,
            "inventory_generation": 11,
            "inventory_revision": 12,
            "destination_ipv4": "1.1.1.1",
            "destination_port": 443,
            "l4_protocol": "tcp",
            "ttl_seconds": 120,
            "detector_rule": RULE,
            "detector_rule_version": RULE_VERSION,
            "detector_bundle_sha256": DETECTOR_BUNDLE_SHA256,
            "coverage_snapshot_sha256": "1" * 64,
            "docker_network_snapshot_sha256": "2" * 64,
            "special_use_registry_sha256": "3" * 64,
            "operator_denylist_sha256": "4" * 64,
            "management_denylist_sha256": "5" * 64,
            "evidence_ids": (PRIMARY_EVENT_ID, SNAPSHOT_EVENT_ID),
            "created_at": "2026-07-27T12:00:05.123456789Z",
        },
        strict=True,
    )


def _fact_models(index: int) -> tuple[IncidentV1, ContainmentCandidateV1, str]:
    primary_character, snapshot_character, coverage_character = (
        ("a", "b", "c") if index == 0 else ("d", "e", "f")
    )
    primary_event_id = "evt_" + primary_character * 64
    snapshot_event_id = "evt_" + snapshot_character * 64
    coverage_event_id = "evt_" + coverage_character * 64
    container_id = ("f" if index == 0 else "e") * 64
    sequence = 1 + index * 3
    incident_identifier = derive_incident_id(primary_event_id)
    candidate_identifier = derive_candidate_id(
        primary_event_id,
        container_id,
        STARTED_AT,
        "1.1.1.1",
        DETECTOR_BUNDLE_SHA256,
    )
    incident = IncidentV1.model_validate(
        {
            **_incident().model_dump(mode="python"),
            "incident_id": incident_identifier,
            "primary_event_id": primary_event_id,
            "primary_source_sequence": sequence,
            "docker_container_id": container_id,
            "evidence_ids": (primary_event_id, snapshot_event_id),
            "authority_event_id": snapshot_event_id,
        },
        strict=True,
    )
    candidate = ContainmentCandidateV1.model_validate(
        {
            **_candidate().model_dump(mode="python"),
            "candidate_id": candidate_identifier,
            "incident_id": incident_identifier,
            "primary_event_id": primary_event_id,
            "primary_source_sequence": sequence,
            "correlation_snapshot_event_id": snapshot_event_id,
            "docker_container_id": container_id,
            "evidence_ids": (primary_event_id, snapshot_event_id),
        },
        strict=True,
    )
    return incident, candidate, coverage_event_id


def _insert_event(connection: sqlite3.Connection, event_id: str, sequence: int) -> None:
    columns = (
        "event_id",
        "host_id",
        "source_sequence",
        "event_type",
        "source_id",
        "source_version",
        "key_id",
        "key_epoch",
        "boot_id",
        "event_time",
        "ingest_time",
        "clock_uncertainty_ms",
        "container_id",
        "container_start_time",
        "release_id",
        "inventory_generation",
        "inventory_revision",
        "normalized_fields_json",
        "normalized_fields_sha256",
        "redaction_flags_json",
        "coverage_flags_json",
        "source_payload_hash",
        "source_signature",
        "segment_id",
        "segment_relative_path",
        "frame_offset",
        "frame_size",
        "frame_sha256",
        "canonical_sha256",
        "content_sha256",
        "duplicate_of_event_id",
    )
    values: tuple[object, ...] = (
        event_id,
        MODEL_HOST_ID,
        f"{sequence:020d}",
        "test_event",
        "agmind-observerd",
        "0.1.0",
        "key",
        "00000000000000000001",
        MODEL_BOOT_ID,
        STARTED_AT,
        STARTED_AT,
        0,
        None,
        None,
        None,
        "00000000000000000001",
        None,
        "{}",
        "1" * 64,
        "[]",
        "[]",
        "2" * 64,
        "signature",
        f"segment-{sequence}",
        f"segments/{sequence}",
        f"{sequence:020d}",
        "00000000000000000001",
        "3" * 64,
        "4" * 64,
        "5" * 64,
        None,
    )
    connection.execute(
        f"INSERT INTO events({','.join(columns)}) VALUES({','.join('?' for _ in values)})",
        values,
    )


def _snapshot_fixture(subject: Any, *, reverse: bool) -> sqlite3.Connection:
    connection = subject._v2_connection_for_test()
    facts = [_fact_models(0), _fact_models(1)]
    event_items: list[tuple[str, int]] = []
    for incident, candidate, coverage_event_id in facts:
        event_items.extend(
            [
                (incident.primary_event_id, incident.primary_source_sequence),
                (candidate.correlation_snapshot_event_id, incident.primary_source_sequence + 1),
                (coverage_event_id, incident.primary_source_sequence + 2),
            ]
        )
    for event_id, sequence in reversed(event_items) if reverse else event_items:
        _insert_event(connection, event_id, sequence)
    ordered_facts = list(reversed(facts)) if reverse else facts
    for incident, _candidate_model, _coverage_event_id in ordered_facts:
        connection.execute(
            f"INSERT INTO incidents({','.join(subject._INCIDENT_COLUMNS)}) "
            f"VALUES({','.join('?' for _ in subject._INCIDENT_COLUMNS)})",
            subject._encode_incident(incident, "candidate"),
        )
    for _incident_model, candidate, _coverage_event_id in ordered_facts:
        connection.execute(
            f"INSERT INTO candidates({','.join(subject._CANDIDATE_COLUMNS)}) "
            f"VALUES({','.join('?' for _ in subject._CANDIDATE_COLUMNS)})",
            subject._encode_candidate(candidate),
        )
    for incident, candidate, coverage_event_id in ordered_facts:
        evidence_rows = (
            subject._encode_candidate_evidence(
                candidate.candidate_id,
                incident.primary_event_id,
                incident.primary_source_sequence,
                "6" * 64,
                "primary_trigger",
                candidate.correlation_snapshot_event_id,
            ),
            subject._encode_candidate_evidence(
                candidate.candidate_id,
                candidate.correlation_snapshot_event_id,
                incident.primary_source_sequence + 1,
                "7" * 64,
                "correlation_snapshot",
                candidate.correlation_snapshot_event_id,
            ),
        )
        for evidence in reversed(evidence_rows) if reverse else evidence_rows:
            connection.execute(
                "INSERT INTO candidate_evidence VALUES(?,?,?,?,?,?)",
                evidence,
            )
        connection.execute(
            "INSERT INTO candidate_invalidations VALUES(?,?,?,?,?)",
            subject._encode_candidate_invalidation(
                candidate.candidate_id,
                coverage_event_id,
                incident.primary_source_sequence + 2,
                "8" * 64,
                "late_critical_coverage_gap",
            ),
        )
    return connection


def test_schema_v1_is_the_exact_active_v1_bytes() -> None:
    root = Path(__file__).parents[2] / "agmind_immune" / "evidence"
    assert (root / "schema_v1.sql").read_bytes() == (root / "schema.sql").read_bytes()


def test_schema_v2_bytes_and_active_v1_dormancy_are_frozen() -> None:
    subject = _subject()
    root = Path(__file__).parents[2] / "agmind_immune" / "evidence"
    expected_schema_hash = "d4a5d563ca3964cbe4ed276882a4b4def95fb756fc67a6777fddf5de38b1619d"
    assert subject._SCHEMA_V2_SHA256 == expected_schema_hash
    assert hashlib.sha256((root / "schema_v2.sql").read_bytes()).hexdigest() == (
        expected_schema_hash
    )
    active = importlib.import_module("agmind_immune.evidence.projection")
    assert active._SCHEMA_META == {
        "schema_version": "agmind.projection-schema.v1",
        "reducer_version": "agmind.projection-reducer.v1",
        "snapshot_layout": "AGMIND_PROJECTION_SNAPSHOT_V1",
    }
    assert active._SNAPSHOT_DOMAIN == b"AGMIND_PROJECTION_SNAPSHOT_V1\0"
    assert tuple(item[0] for item in active._TABLE_LAYOUT) == (
        "schema_meta",
        "events",
        "projection_dedup",
        "coverage_intervals",
        "containers",
        "process_observations",
        "network_observations",
        "ingest_cursors",
    )
    assert subject._SCHEMA_V2_PATH.name == "schema_v2.sql"
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        active._create_schema(connection)
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            )
        }
        assert "incidents" not in tables
        assert dict(connection.execute("SELECT key,value FROM schema_meta")) == active._SCHEMA_META
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("image", "expected", "v1_verifications", "v2_verifications"),
    (
        ("absent", "new", 0, 0),
        ("zero-length", "unknown", 0, 0),
        ("v1", "v1", 1, 0),
        ("v2", "v2", 0, 1),
        ("v1-altered-view", "unknown", 1, 0),
        ("v2-altered-index", "unknown", 0, 1),
    ),
)
def test_projection_image_classifier_is_read_only_and_exact_for_new_v1_v2_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    image: str,
    expected: str,
    v1_verifications: int,
    v2_verifications: int,
) -> None:
    """Catches mutating probes, loose V1/V2 selection, and V2-to-V1 fallback."""
    active = importlib.import_module("agmind_immune.evidence.projection")
    subject = _subject()
    root = tmp_path / image
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    path = root / "projection.sqlite3"
    _create_projection_image(active, subject, path, image)

    schema_v1 = Path(active.__file__).with_name("schema_v1.sql")
    assert active._SCHEMA_V1_PATH == schema_v1
    assert active._SCHEMA_V1_SHA256 == (
        "e27ea065b3659197aae7b58939695a5e79439faeb0b841dc600c6c822b1919f2"
    )
    assert hashlib.sha256(schema_v1.read_bytes()).hexdigest() == active._SCHEMA_V1_SHA256

    calls = {"v1": 0, "v2": 0}
    real_v1 = active._verify_v1_schema
    real_v2 = subject._verify_v2_schema

    def count_v1(*args: object, **kwargs: object) -> None:
        calls["v1"] += 1
        real_v1(*args, **kwargs)

    def count_v2(*args: object, **kwargs: object) -> None:
        calls["v2"] += 1
        real_v2(*args, **kwargs)

    monkeypatch.setattr(active, "_verify_v1_schema", count_v1)
    monkeypatch.setattr(subject, "_verify_v2_schema", count_v2)

    parent_fd = active._validate_parent(root)
    lock_fd = active._open_stable_lock(
        parent_fd,
        f".{path.name}.projection.lock",
    )
    try:
        existing = active._lstat_at(parent_fd, path.name)
        main_binding = (
            None
            if existing is None
            else active._bind_regular_at(
                parent_fd,
                path.name,
                label="projection database",
            )
        )
        before = _projection_image_artifacts(path)

        classified = active._classify_projection_image_locked(
            path,
            parent_fd=parent_fd,
            main_binding=main_binding,
        )

        assert classified is active._ProjectionImageKind(expected)
        assert calls == {"v1": v1_verifications, "v2": v2_verifications}
        assert _projection_image_artifacts(path) == before
    finally:
        os.close(lock_fd)
        os.close(parent_fd)


def test_projection_import_orders_do_not_form_a_cycle() -> None:
    """Catches making Projection V2 an eager dependency of active Projection V1."""
    root = Path(__file__).parents[3]
    environment = dict(os.environ)
    python_path = str(root / "core")
    if environment.get("PYTHONPATH"):
        python_path = f"{python_path}{os.pathsep}{environment['PYTHONPATH']}"
    environment["PYTHONPATH"] = python_path
    projection_first = (
        "import importlib, sys\n"
        "p = importlib.import_module('agmind_immune.evidence.projection')\n"
        "assert 'agmind_immune.evidence.projection_v2' not in sys.modules\n"
        "v2 = importlib.import_module('agmind_immune.evidence.projection_v2')\n"
        "assert callable(p._classify_projection_image_locked)\n"
        "assert v2._V2ProjectionOwner.__name__ == '_V2ProjectionOwner'\n"
    )
    v2_first = (
        "import importlib\n"
        "v2 = importlib.import_module('agmind_immune.evidence.projection_v2')\n"
        "p = importlib.import_module('agmind_immune.evidence.projection')\n"
        "assert callable(p._classify_projection_image_locked)\n"
        "assert v2._V2ProjectionOwner.__name__ == '_V2ProjectionOwner'\n"
    )
    for script in (projection_first, v2_first):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("corruption", ["removed_fk", "missing", "unreadable", "non_utf8"])
def test_v2_schema_bytes_are_trusted_before_create_or_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corruption: str,
) -> None:
    subject = _subject()
    verified = subject._v2_connection_for_test()
    blank = sqlite3.connect(":memory:", isolation_level=None)
    try:
        if corruption == "removed_fk":
            raw = subject._SCHEMA_V2_PATH.read_bytes()
            authority_fks = (
                b"    FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id),\n"
                b"    FOREIGN KEY(authority_snapshot_event_id) REFERENCES events(event_id)\n"
            )
            assert authority_fks in raw
            path = tmp_path / "schema-removed-fk.sql"
            path.write_bytes(
                raw.replace(
                    authority_fks,
                    b"    FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id)\n",
                )
            )
        elif corruption == "missing":
            path = tmp_path / "missing.sql"
        elif corruption == "unreadable":
            path = tmp_path / "schema-directory"
            path.mkdir()
        else:
            path = tmp_path / "schema-invalid-utf8.sql"
            path.write_bytes(b"\xff\xfe")
        monkeypatch.setattr(subject, "_SCHEMA_V2_PATH", path)
        with pytest.raises(subject.ProjectionConflict):
            subject._create_v2_schema(blank)
        with pytest.raises(subject.ProjectionConflict):
            subject._verify_v2_schema(verified)
    finally:
        blank.close()
        verified.close()


def test_v2_schema_identity_table_order_and_indexes_are_frozen() -> None:
    subject = _subject()
    assert subject._SCHEMA_META_V2 == {
        "schema_version": "agmind.projection-schema.v2",
        "reducer_version": "agmind.projection-reducer.v2",
        "dedup_version": "AGMIND_PROJECTION_DEDUP_V2",
        "snapshot_layout": "AGMIND_PROJECTION_SNAPSHOT_V2",
    }
    assert subject._SNAPSHOT_DOMAIN_V2 == b"AGMIND_PROJECTION_SNAPSHOT_V2\0"
    assert tuple(item[0] for item in subject._TABLE_LAYOUT_V2) == (
        "schema_meta",
        "events",
        "projection_dedup",
        "coverage_intervals",
        "containers",
        "process_observations",
        "network_observations",
        "incidents",
        "candidates",
        "candidate_evidence",
        "candidate_invalidations",
        "ingest_cursors",
    )
    assert subject._TABLE_NAMES_V2 == frozenset(item[0] for item in subject._TABLE_LAYOUT_V2)
    assert all(
        "projection_generation" not in columns
        for _table, columns, _primary_key in subject._TABLE_LAYOUT_V2
    )

    connection = subject._v2_connection_for_test()
    try:
        subject._verify_v2_schema(connection)
        objects = _schema_objects(connection)
        assert dict(connection.execute("SELECT key,value FROM schema_meta ORDER BY key")) == (
            subject._SCHEMA_META_V2
        )
        for table, columns, primary_key in subject._TABLE_LAYOUT_V2:
            info = connection.execute(f"PRAGMA table_info({table})").fetchall()
            assert tuple(str(row[1]) for row in info) == columns
            assert tuple(
                str(row[1]) for row in sorted(info, key=lambda row: int(row[5])) if row[5]
            ) == primary_key
        indexes = {
            tuple(str(item[2]) for item in connection.execute(f"PRAGMA index_info({name})"))
            for name, sql in objects.items()
            if sql.startswith("CREATE INDEX")
        }
        assert ("source_sequence", "event_id") in indexes
        assert (
            "host_id",
            "boot_id",
            "docker_container_id",
            "docker_started_at",
            "detector_bundle_sha256",
            "destination_ipv4",
            "primary_source_sequence",
            "primary_event_id",
            "candidate_id",
        ) in indexes
        assert ("candidate_id", "authority_snapshot_event_id") in indexes
        assert ("candidate_id",) in indexes
    finally:
        connection.close()


def test_v2_foreign_keys_preserve_retention_boundaries() -> None:
    subject = _subject()
    connection = subject._v2_connection_for_test()
    try:
        incident_fks = {
            (str(row[3]), str(row[2]), str(row[4]))
            for row in connection.execute("PRAGMA foreign_key_list(incidents)")
        }
        candidate_fks = {
            (str(row[3]), str(row[2]), str(row[4]))
            for row in connection.execute("PRAGMA foreign_key_list(candidates)")
        }
        evidence_fks = {
            (str(row[3]), str(row[2]), str(row[4]))
            for row in connection.execute("PRAGMA foreign_key_list(candidate_evidence)")
        }
        assert incident_fks == {("authority_event_id", "events", "event_id")}
        assert candidate_fks == {
            ("incident_id", "incidents", "incident_id"),
            ("correlation_snapshot_event_id", "events", "event_id"),
        }
        assert evidence_fks == {
            ("candidate_id", "candidates", "candidate_id"),
            ("authority_snapshot_event_id", "events", "event_id"),
        }
        assert not any(column == "primary_event_id" for column, _, _ in incident_fks)
        assert not any(column == "primary_event_id" for column, _, _ in candidate_fks)
        assert not any(column == "evidence_event_id" for column, _, _ in evidence_fks)
    finally:
        connection.close()


def test_prepare_v2_uses_only_the_boot_aware_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    subject = _subject()
    record = _record()
    envelope = EventEnvelopeV1.model_validate(record.envelope, strict=True)
    expected = _logical_primary_identity_v2(envelope)

    def boot_blind_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("boot-blind V1 dedup was called")

    projection = importlib.import_module("agmind_immune.evidence.projection")
    monkeypatch.setattr(projection, "_prepare", boot_blind_must_not_run)
    monkeypatch.setattr(
        importlib.import_module("agmind_immune.evidence.dedup"),
        "_logical_primary_identity_v1",
        boot_blind_must_not_run,
    )
    prepared = subject._prepare_v2(record)
    assert (prepared.dedup_kind, prepared.logical_key_sha256) == expected


@pytest.mark.parametrize(
    "corruption",
    [
        "canonical_bytes_subclass",
        "priority_string",
        "accepted_at_subclass",
        "accepted_at_invalid",
        "source_sequence_bool",
        "frame_offset_bool",
        "frame_offset_negative",
        "frame_size_float",
        "frame_size_oversized",
        "segment_id",
        "segment_path",
        "event_id_subclass",
        "frame_hash_subclass",
        "content_hash_subclass",
    ],
)
def test_prepare_v2_rejects_non_exact_record_and_ref_facts(corruption: str) -> None:
    subject = _subject()
    record = _record()
    ref = record.ref
    if corruption == "canonical_bytes_subclass":
        record = replace(record, canonical_envelope=_BytesSubclass(record.canonical_envelope))
    elif corruption == "priority_string":
        record = replace(record, priority="routine")
    elif corruption == "accepted_at_subclass":
        record = replace(record, accepted_at=_StringSubclass(record.accepted_at))
    elif corruption == "accepted_at_invalid":
        record = replace(record, accepted_at="2026-07-28 10:00:00")
    elif corruption == "source_sequence_bool":
        record = replace(record, ref=replace(ref, source_sequence=True))
    elif corruption == "frame_offset_bool":
        record = replace(record, ref=replace(ref, frame_offset=True))
    elif corruption == "frame_offset_negative":
        record = replace(record, ref=replace(ref, frame_offset=-1))
    elif corruption == "frame_size_float":
        record = replace(record, ref=replace(ref, frame_size=float(ref.frame_size)))
    elif corruption == "frame_size_oversized":
        record = replace(record, ref=replace(ref, frame_size=2**64))
    elif corruption == "segment_id":
        record = replace(record, ref=replace(ref, segment_id="not-a-segment"))
    elif corruption == "segment_path":
        record = replace(record, ref=replace(ref, segment_relative_path="segments/controlled"))
    elif corruption == "event_id_subclass":
        record = replace(record, ref=replace(ref, event_id=_StringSubclass(ref.event_id)))
    elif corruption == "frame_hash_subclass":
        record = replace(
            record,
            ref=replace(ref, frame_sha256=_StringSubclass(ref.frame_sha256)),
        )
    else:
        record = replace(
            record,
            ref=replace(ref, content_sha256=_StringSubclass(ref.content_sha256)),
        )
    with pytest.raises(subject.ProjectionValidationError):
        subject._prepare_v2(record)


@pytest.mark.parametrize(
    ("incident", "result_kind"),
    [(_incident(), "candidate"), (_incident(direct=True), "investigation")],
)
def test_incident_codec_round_trips_exact_models_and_absent_optionals(
    incident: IncidentV1,
    result_kind: str,
) -> None:
    subject = _subject()
    assert subject._INCIDENT_COLUMNS == tuple(IncidentV1.model_fields) + ("result_kind",)
    encoded = subject._encode_incident(incident, result_kind)
    by_name = dict(zip(subject._INCIDENT_COLUMNS, encoded, strict=True))
    assert by_name["primary_source_sequence"] == "00000000000000000007"
    assert type(by_name["successful_connect"]) is int
    assert by_name["successful_connect"] == 1
    assert by_name["evidence_ids"] == canonical_json(incident.evidence_ids).decode()
    if incident.investigation_only:
        assert by_name["docker_container_id"] is None
        assert by_name["destination_port"] is None
    decoded, decoded_kind = subject._decode_incident(encoded)
    assert (decoded, decoded_kind) == (incident, result_kind)
    assert decoded.model_fields_set == incident.model_fields_set


def test_candidate_codec_round_trips_and_binds_the_full_facts_hash() -> None:
    subject = _subject()
    candidate = _candidate()
    assert subject._CANDIDATE_COLUMNS == tuple(ContainmentCandidateV1.model_fields) + (
        "candidate_facts_sha256",
    )
    encoded = subject._encode_candidate(candidate)
    by_name = dict(zip(subject._CANDIDATE_COLUMNS, encoded, strict=True))
    assert by_name["primary_source_sequence"] == "00000000000000000007"
    assert by_name["inventory_generation"] == "00000000000000000011"
    assert by_name["inventory_revision"] == "00000000000000000012"
    assert by_name["repo_digests"] == canonical_json(candidate.repo_digests).decode()
    assert by_name["candidate_facts_sha256"] == candidate_facts_sha256(candidate)
    assert subject._decode_candidate(encoded) == candidate
    assert subject._candidate_duplicate_key_from_row(encoded) == (
        MODEL_HOST_ID,
        MODEL_BOOT_ID,
        CONTAINER_ID,
        STARTED_AT,
        DETECTOR_BUNDLE_SHA256,
        "1.1.1.1",
    )


def test_incident_encoder_rejects_model_copy_explicit_null_laundering() -> None:
    subject = _subject()
    forged = _incident().model_copy(update={"docker_container_id": None})
    assert "docker_container_id" in forged.model_fields_set
    with pytest.raises((TypeError, ValueError)):
        subject._encode_incident(forged, "candidate")


@pytest.mark.parametrize("forgery", ["model_copy", "object_setattr"])
def test_candidate_encoder_rejects_unvalidated_detector_hash(forgery: str) -> None:
    subject = _subject()
    candidate = _candidate()
    if forgery == "model_copy":
        forged = candidate.model_copy(update={"detector_bundle_sha256": "invalid"})
    else:
        object.__setattr__(candidate, "detector_bundle_sha256", "invalid")
        forged = candidate
    with pytest.raises((TypeError, ValueError)):
        subject._encode_candidate(forged)


def test_evidence_and_invalidation_codecs_round_trip_exact_rows() -> None:
    subject = _subject()
    evidence = (
        CANDIDATE_ID,
        PRIMARY_EVENT_ID,
        7,
        "6" * 64,
        "primary_trigger",
        SNAPSHOT_EVENT_ID,
    )
    encoded_evidence = subject._encode_candidate_evidence(*evidence)
    assert encoded_evidence[2] == "00000000000000000007"
    assert subject._decode_candidate_evidence(encoded_evidence) == evidence

    invalidation = (
        CANDIDATE_ID,
        "evt_" + "c" * 64,
        9,
        "7" * 64,
        "late_critical_coverage_gap",
    )
    encoded_invalidation = subject._encode_candidate_invalidation(*invalidation)
    assert encoded_invalidation[2] == "00000000000000000009"
    assert subject._decode_candidate_invalidation(encoded_invalidation) == invalidation


@pytest.mark.parametrize(
    ("column", "hostile"),
    [
        ("primary_source_sequence", "7"),
        ("primary_source_sequence", "18446744073709551616"),
        ("successful_connect", 2),
        ("missing_required_fields", "[ ]"),
        ("missing_required_fields", "[NaN]"),
        ("evidence_ids", f'["{SNAPSHOT_EVENT_ID}","{PRIMARY_EVENT_ID}"]'),
        ("reason_codes", '["investigation_only","investigation_only"]'),
        ("result_kind", "safe"),
    ],
)
def test_incident_decoder_rejects_hostile_persisted_rows(
    column: str,
    hostile: object,
) -> None:
    subject = _subject()
    values = list(subject._encode_incident(_incident(), "candidate"))
    values[subject._INCIDENT_COLUMNS.index(column)] = hostile
    connection, row = _persist_hostile_row(
        subject, "incidents", subject._INCIDENT_COLUMNS, tuple(values)
    )
    try:
        with pytest.raises(subject.ProjectionConflict):
            subject._decode_incident(row)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("column", "hostile"),
    [
        ("inventory_generation", "11"),
        ("repo_digests", "[ ]"),
        ("repo_digests", '["z","z"]'),
        ("candidate_facts_sha256", "0" * 64),
        ("candidate_facts_sha256", "A" * 64),
        ("ttl_seconds", 120.5),
    ],
)
def test_candidate_decoder_rejects_hostile_persisted_rows(
    column: str,
    hostile: object,
) -> None:
    subject = _subject()
    values = list(subject._encode_candidate(_candidate()))
    values[subject._CANDIDATE_COLUMNS.index(column)] = hostile
    connection, row = _persist_hostile_row(
        subject, "candidates", subject._CANDIDATE_COLUMNS, tuple(values)
    )
    try:
        with pytest.raises(subject.ProjectionConflict):
            subject._decode_candidate(row)
        with pytest.raises(subject.ProjectionConflict):
            subject._candidate_duplicate_key_from_row(row)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("table", "decoder", "values"),
    [
        (
            "candidate_evidence",
            "_decode_candidate_evidence",
            (CANDIDATE_ID, PRIMARY_EVENT_ID, "7", "6" * 64, "primary_trigger", SNAPSHOT_EVENT_ID),
        ),
        (
            "candidate_evidence",
            "_decode_candidate_evidence",
            (CANDIDATE_ID, PRIMARY_EVENT_ID, "00000000000000000007", "6" * 64, "primary", SNAPSHOT_EVENT_ID),
        ),
        (
            "candidate_invalidations",
            "_decode_candidate_invalidation",
            (CANDIDATE_ID, "evt_" + "c" * 64, "9", "7" * 64, "late_critical_coverage_gap"),
        ),
        (
            "candidate_invalidations",
            "_decode_candidate_invalidation",
            (CANDIDATE_ID, "evt_" + "c" * 64, "00000000000000000009", "7" * 64, "late_gap"),
        ),
    ],
)
def test_security_row_decoders_reject_hostile_persisted_rows(
    table: str,
    decoder: str,
    values: tuple[object, ...],
) -> None:
    subject = _subject()
    layout = next(item for item in subject._TABLE_LAYOUT_V2 if item[0] == table)
    connection, row = _persist_hostile_row(subject, table, layout[1], values)
    try:
        with pytest.raises(subject.ProjectionConflict):
            getattr(subject, decoder)(row)
    finally:
        connection.close()


@pytest.mark.parametrize("mutation", ["table", "view", "trigger", "index", "meta", "pragma"])
def test_schema_verifier_rejects_every_object_metadata_and_pragma_mutation(
    mutation: str,
) -> None:
    subject = _subject()
    connection = subject._v2_connection_for_test()
    try:
        if mutation == "table":
            connection.execute("CREATE TABLE extra(value TEXT)")
        elif mutation == "view":
            connection.execute("CREATE VIEW extra AS SELECT key FROM schema_meta")
        elif mutation == "trigger":
            connection.execute(
                "CREATE TRIGGER extra AFTER INSERT ON schema_meta BEGIN SELECT 1; END"
            )
        elif mutation == "index":
            connection.execute("DROP INDEX candidate_invalidations_candidate")
        elif mutation == "meta":
            connection.execute(
                "UPDATE schema_meta SET value='changed' WHERE key='reducer_version'"
            )
        else:
            connection.execute("PRAGMA ignore_check_constraints=ON")
        with pytest.raises(subject.ProjectionConflict):
            subject._verify_v2_schema(connection)
    finally:
        connection.close()


def test_shuffled_insertion_has_stable_full_pk_order_and_v2_snapshot() -> None:
    subject = _subject()
    empty_first = subject._v2_connection_for_test()
    empty_second = subject._v2_connection_for_test()
    forward = _snapshot_fixture(subject, reverse=False)
    reverse = _snapshot_fixture(subject, reverse=True)
    try:
        assert subject._v2_snapshot_hash(empty_first) == subject._v2_snapshot_hash(empty_second)
        for table, _columns, _primary_key in subject._TABLE_LAYOUT_V2:
            assert subject._v2_ordered_table_rows(forward, table) == (
                subject._v2_ordered_table_rows(reverse, table)
            )
        forward_evidence = subject._v2_ordered_table_rows(forward, "candidate_evidence")
        assert forward_evidence == sorted(
            forward_evidence,
            key=lambda row: (row[0], row[1], row[4], row[5]),
        )
        first_hash = subject._v2_snapshot_hash(forward)
        assert first_hash == subject._v2_snapshot_hash(reverse)
        assert len(first_hash) == 64
        assert first_hash != hashlib.sha256(
            b"AGMIND_PROJECTION_SNAPSHOT_V1\0"
        ).hexdigest()
        forward.execute(
            "UPDATE events SET source_signature=source_signature || 'x' "
            "WHERE event_id=?",
            (PRIMARY_EVENT_ID,),
        )
        assert subject._v2_snapshot_hash(forward) != first_hash
    finally:
        empty_first.close()
        empty_second.close()
        forward.close()
        reverse.close()


def test_snapshot_hash_preserves_caller_owned_transaction_and_uncommitted_rows() -> None:
    subject = _subject()
    connection = subject._v2_connection_for_test()
    try:
        baseline = subject._v2_snapshot_hash(connection)
        connection.execute("BEGIN")
        _insert_event(connection, PRIMARY_EVENT_ID, 1)
        assert connection.in_transaction
        transaction_hash = subject._v2_snapshot_hash(connection)
        assert transaction_hash != baseline
        assert connection.in_transaction
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        connection.execute("ROLLBACK")
        assert not connection.in_transaction
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        assert subject._v2_snapshot_hash(connection) == baseline
    finally:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        connection.close()


def test_snapshot_hash_conflict_does_not_rollback_caller_owned_transaction() -> None:
    subject = _subject()
    connection = _snapshot_fixture(subject, reverse=False)
    try:
        baseline = subject._v2_snapshot_hash(connection)
        connection.execute("BEGIN")
        connection.execute(
            "UPDATE candidates SET candidate_facts_sha256=? WHERE candidate_id=?",
            ("0" * 64, CANDIDATE_ID),
        )
        with pytest.raises(subject.ProjectionConflict):
            subject._v2_snapshot_hash(connection)
        assert connection.in_transaction
        assert connection.execute(
            "SELECT candidate_facts_sha256 FROM candidates WHERE candidate_id=?",
            (CANDIDATE_ID,),
        ).fetchone()[0] == "0" * 64
        connection.execute("ROLLBACK")
        assert subject._v2_snapshot_hash(connection) == baseline
    finally:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        connection.close()
