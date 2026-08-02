from __future__ import annotations

import copy
import gc
import importlib
import inspect
import os
import pickle
import shutil
import stat
import weakref
from collections.abc import Callable
from dataclasses import dataclass, replace
from ipaddress import IPv4Address
from pathlib import Path
from threading import Barrier, Event, Thread
from types import ModuleType
from typing import cast

import pytest
from agmind_immune.canonicaljson import (
    candidate_id,
    canonical_json,
    pcc_detector_bundle_sha256,
)
from agmind_immune.correlation.pcc import (
    ActiveCandidateObservation,
    CandidateCreated,
    CandidateDuplicateKey,
    CorrelationContext,
    CorrelationProjectionError,
    Rejected,
    TerminalCandidateObservation,
    correlate_pcc,
    correlate_pcc_facts,
)
from agmind_immune.correlation.primitives import (
    GlobalReachability,
    load_pinned_special_use_registry,
)
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import AuthenticatedPCCInput
from agmind_immune.ingest.service import AcceptanceCoordinator
from tests.correlation.test_pcc import (
    _accepted_complete,
    _accepted_failed,
    _context,
    _duplicate_key,
)
from tests.evidence.test_retention_restart import _fresh_verifier
from tests.ingest.test_correlation_journal import (
    _append_payload,
    read_correlation_frame_payloads,
)
from tests.ingest.test_pcc_correlation_snapshot import _accept
from tests.phase5b_helpers import envelope_value, private_key

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_RULE_PATH = "/etc/falco/rules.d/agmind-pcc.yaml"
_PARENTS = ("/", "/etc", "/etc/falco", "/etc/falco/rules.d")
_MAX_RULE_BYTES = 65_536
_PINNED_RULE_HASH = "9adde9efa900af138a8785b7f313582e8e3688e6ec39fd8045c275841b3880cc"
_PCC_DETECTOR_HASH = "1" * 64
_REGISTRY_PATH = Path("contracts/v1/ipv4-special-use.csv")


class _LayoutCompatibleCorrelationContext(CorrelationContext):
    __slots__ = ()


def _authority_module() -> ModuleType:
    try:
        return importlib.import_module("agmind_immune.correlation.authority")
    except ModuleNotFoundError:
        pytest.fail("the fixed detector authority module is missing")


@dataclass(frozen=True)
class _FakeStat:
    st_dev: int
    st_ino: int
    st_mode: int
    st_nlink: int
    st_uid: int
    st_gid: int
    st_size: int
    st_mtime_ns: int = 1
    st_ctime_ns: int = 1


type _Override = dict[str, int] | bytes | BaseException


class _FakeFilesystem:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.nodes = {
            path: _FakeStat(
                st_dev=1,
                st_ino=index,
                st_mode=stat.S_IFDIR | 0o755,
                st_nlink=2,
                st_uid=0,
                st_gid=0,
                st_size=0,
            )
            for index, path in enumerate(_PARENTS, start=1)
        }
        self.nodes[_RULE_PATH] = _FakeStat(
            st_dev=1,
            st_ino=5,
            st_mode=stat.S_IFREG | 0o444,
            st_nlink=1,
            st_uid=0,
            st_gid=0,
            st_size=len(raw),
        )
        self.overrides: dict[tuple[str, str, int], _Override] = {}
        self.calls: dict[tuple[str, str], int] = {}
        self.open_calls: list[tuple[str, int, int | None]] = []
        self.stat_calls: list[tuple[str, int | None, bool]] = []
        self.read_calls: list[tuple[int, int]] = []
        self.closed: list[int] = []
        self._descriptors: dict[int, str] = {}
        self._next_descriptor = 10

    def replace_node(self, path: str, **changes: int) -> None:
        self.nodes[path] = replace(self.nodes[path], **changes)

    def _path(self, name: str, dir_fd: int | None) -> str:
        if name == "/" and dir_fd is None:
            return "/"
        if name.startswith("/") or dir_fd is None:
            raise OSError("unsafe absolute or unanchored path")
        parent = self._descriptors[dir_fd]
        return f"/{name}" if parent == "/" else f"{parent}/{name}"

    def _next(self, operation: str, path: str) -> _Override | None:
        key = (operation, path)
        occurrence = self.calls.get(key, 0) + 1
        self.calls[key] = occurrence
        return self.overrides.get((operation, path, occurrence))

    @staticmethod
    def _raise_or_replace(base: _FakeStat, override: _Override | None) -> _FakeStat:
        if isinstance(override, BaseException):
            raise override
        if isinstance(override, bytes):
            raise TypeError("bytes override used for a stat operation")
        if override is None:
            return base
        return replace(base, **override)

    def stat(
        self,
        name: str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> _FakeStat:
        path = self._path(name, dir_fd)
        self.stat_calls.append((name, dir_fd, follow_symlinks))
        return self._raise_or_replace(
            self.nodes[path],
            self._next("stat", path),
        )

    def open(self, name: str, flags: int, *, dir_fd: int | None = None) -> int:
        path = self._path(name, dir_fd)
        override = self._next("open", path)
        if isinstance(override, BaseException):
            raise override
        if override is not None:
            raise AssertionError("open overrides must be exceptions")
        descriptor = self._next_descriptor
        self._next_descriptor += 1
        self._descriptors[descriptor] = path
        self.open_calls.append((name, flags, dir_fd))
        return descriptor

    def fstat(self, descriptor: int) -> _FakeStat:
        path = self._descriptors[descriptor]
        return self._raise_or_replace(
            self.nodes[path],
            self._next("fstat", path),
        )

    def read(self, descriptor: int, count: int) -> bytes:
        path = self._descriptors[descriptor]
        override = self._next("read", path)
        self.read_calls.append((descriptor, count))
        if isinstance(override, BaseException):
            raise override
        if isinstance(override, dict):
            raise TypeError("stat override used for a read operation")
        if isinstance(override, bytes):
            return override
        return self.raw[:count]

    def close(self, descriptor: int) -> None:
        self.closed.append(descriptor)


def _loader(filesystem: _FakeFilesystem):
    authority = _authority_module()
    factory = getattr(authority, "_detector_bundle_loader", None)
    if factory is None:
        pytest.fail("the private detector-loader factory is missing")
    return factory(filesystem)


def _assert_unavailable(filesystem: _FakeFilesystem) -> None:
    with pytest.raises(RuntimeError, match="detector bundle"):
        _loader(filesystem)()


def test_production_loader_is_fixed_no_argument_private_api() -> None:
    authority = _authority_module()
    loader = getattr(authority, "_load_pinned_detector_bundle", None)

    assert loader is not None
    assert tuple(inspect.signature(loader).parameters) == ()
    assert not hasattr(authority, "load_pinned_detector_bundle")
    assert not hasattr(authority, "detector_bundle_loader")


def test_fixed_loader_hashes_exact_repository_rule_and_walks_from_root() -> None:
    raw = (_REPOSITORY_ROOT / "deploy/falco/rules.d/agmind-pcc.yaml").read_bytes()
    filesystem = _FakeFilesystem(raw)

    actual = _loader(filesystem)()

    assert actual == _PINNED_RULE_HASH
    assert actual == pcc_detector_bundle_sha256(raw)
    assert [call[0] for call in filesystem.open_calls] == [
        "/",
        "etc",
        "falco",
        "rules.d",
        "agmind-pcc.yaml",
    ]
    assert filesystem.open_calls[0][2] is None
    assert all(call[2] is not None for call in filesystem.open_calls[1:])
    assert all(flags & os.O_NOFOLLOW for _, flags, _ in filesystem.open_calls)
    assert all(flags & os.O_DIRECTORY for _, flags, _ in filesystem.open_calls[:-1])
    assert all(not follow for _, _, follow in filesystem.stat_calls)
    assert filesystem.read_calls == [(14, _MAX_RULE_BYTES + 1)]
    assert sorted(filesystem.closed) == [10, 11, 12, 13, 14]


_PARENT_INVALID_FACTS = (
    {"st_mode": stat.S_IFREG | 0o755},
    {"st_mode": stat.S_IFLNK | 0o777},
    {"st_uid": 1},
    {"st_gid": 1},
    {"st_mode": stat.S_IFDIR | 0o775},
    {"st_mode": stat.S_IFDIR | 0o757},
)


@pytest.mark.parametrize(
    ("path", "changes"),
    [(path, changes) for path in _PARENTS for changes in _PARENT_INVALID_FACTS],
)
def test_loader_rejects_unsafe_parent_facts(path: str, changes: dict[str, int]) -> None:
    filesystem = _FakeFilesystem(b"rule")
    filesystem.replace_node(path, **changes)

    _assert_unavailable(filesystem)


@pytest.mark.parametrize(
    "changes",
    [
        {"st_mode": stat.S_IFDIR | 0o444},
        {"st_mode": stat.S_IFLNK | 0o777},
        {"st_uid": 1},
        {"st_gid": 1},
        {"st_mode": stat.S_IFREG | 0o400},
        {"st_mode": stat.S_IFREG | 0o446},
        {"st_nlink": 2},
    ],
)
def test_loader_rejects_unsafe_file_facts(changes: dict[str, int]) -> None:
    filesystem = _FakeFilesystem(b"rule")
    filesystem.replace_node(_RULE_PATH, **changes)

    _assert_unavailable(filesystem)


def test_loader_rejects_empty_file() -> None:
    _assert_unavailable(_FakeFilesystem(b""))


def test_loader_accepts_exact_size_cap_with_one_bounded_read() -> None:
    raw = b"x" * _MAX_RULE_BYTES
    filesystem = _FakeFilesystem(raw)

    assert _loader(filesystem)() == pcc_detector_bundle_sha256(raw)
    assert filesystem.read_calls == [(14, _MAX_RULE_BYTES + 1)]


def test_loader_rejects_cap_plus_one() -> None:
    _assert_unavailable(_FakeFilesystem(b"x" * (_MAX_RULE_BYTES + 1)))


@pytest.mark.parametrize("returned", [b"rul", b"rule-extra"])
def test_loader_rejects_short_or_extra_read(returned: bytes) -> None:
    filesystem = _FakeFilesystem(b"rule")
    filesystem.overrides[("read", _RULE_PATH, 1)] = returned

    _assert_unavailable(filesystem)


@pytest.mark.parametrize(
    ("operation", "path", "occurrence"),
    [
        ("stat", "/", 1),
        ("open", "/etc", 1),
        ("fstat", "/etc/falco", 1),
        ("stat", _RULE_PATH, 1),
        ("open", _RULE_PATH, 1),
        ("read", _RULE_PATH, 1),
        ("fstat", _RULE_PATH, 2),
        ("stat", _RULE_PATH, 2),
    ],
)
def test_loader_rejects_open_read_and_stat_errors(
    operation: str,
    path: str,
    occurrence: int,
) -> None:
    filesystem = _FakeFilesystem(b"rule")
    filesystem.overrides[(operation, path, occurrence)] = OSError("injected failure")

    _assert_unavailable(filesystem)


@pytest.mark.parametrize(
    ("operation", "occurrence", "changes"),
    [
        ("fstat", 1, {"st_ino": 50}),
        ("fstat", 1, {"st_mtime_ns": 2}),
        ("fstat", 2, {"st_ino": 50}),
        ("fstat", 2, {"st_mtime_ns": 2}),
        ("stat", 2, {"st_ino": 50}),
        ("stat", 2, {"st_mtime_ns": 2}),
    ],
)
def test_loader_rejects_named_open_post_read_or_final_file_drift(
    operation: str,
    occurrence: int,
    changes: dict[str, int],
) -> None:
    filesystem = _FakeFilesystem(b"rule")
    filesystem.overrides[(operation, _RULE_PATH, occurrence)] = changes

    _assert_unavailable(filesystem)


@pytest.mark.parametrize(
    ("operation", "path"),
    [(operation, path) for path in _PARENTS for operation in ("stat", "fstat")],
)
def test_loader_rejects_final_parent_replacement(operation: str, path: str) -> None:
    filesystem = _FakeFilesystem(b"rule")
    filesystem.overrides[(operation, path, 2)] = {"st_ino": 50}

    _assert_unavailable(filesystem)


@dataclass
class _ProjectionCase:
    coordinator: AcceptanceCoordinator
    journal: CorrelationRequestJournal
    completed: object
    authority: object
    predecessor: object
    registry: object
    proof: AuthenticatedPCCInput
    context: CorrelationContext

    def close(self) -> None:
        _authority_module()._close_correlation_projection_authority(  # type: ignore[attr-defined]
            self.authority
        )
        if not getattr(self.journal, "_closed", True):
            self.journal.close()
        store = self.coordinator.segment_store
        if not getattr(store, "_closed", True):
            store.close()


def _empty_predecessor(*, generation: int = 1) -> object:
    authority = _authority_module()
    return authority._ProjectionPredecessor(  # type: ignore[attr-defined]
        generation=generation,
        host_id=None,
        source_sequence=0,
        event_id=None,
        content_sha256=None,
        frame_sha256=None,
    )


def _present_predecessor(
    proof: AuthenticatedPCCInput,
    *,
    generation: int = 1,
    source_sequence: int | None = None,
) -> object:
    authority = _authority_module()
    ref = cast(EvidenceRef, proof.evidence_ref)
    return authority._ProjectionPredecessor(  # type: ignore[attr-defined]
        generation=generation,
        host_id=proof.host_id,
        source_sequence=(
            proof.source_sequence
            if source_sequence is None
            else source_sequence
        ),
        event_id=proof.event_id,
        content_sha256=proof.content_sha256,
        frame_sha256=ref.frame_sha256,
    )


def _projection_case(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    active_duplicate: ActiveCandidateObservation | None = None,
) -> _ProjectionCase:
    authority = _authority_module()
    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        lambda: _PCC_DETECTOR_HASH,
    )
    coordinator, accepted = _accepted_complete(path, ttl_seconds=120)
    trigger_ref = coordinator.verifier.accepted_ref(
        accepted.snapshot.trigger.source_sequence
    )
    assert type(trigger_ref) is EvidenceRef
    journal = CorrelationRequestJournal.create_new(coordinator.segment_store)
    selected = journal.select(trigger_ref, canonical_json(accepted.request))
    snapshot_ref = cast(EvidenceRef, accepted.evidence_ref)
    journal.mark_proof_observed(selected.request_sha256, snapshot_ref)
    journal.mark_completed(selected.request_sha256)
    completed = journal.completed_for_snapshot(snapshot_ref)
    registry = load_pinned_special_use_registry(_REGISTRY_PATH)
    predecessor = _empty_predecessor()
    projection_authority = authority._create_correlation_projection_authority(  # type: ignore[attr-defined]
        coordinator.segment_store,
        registry,
        predecessor,
    )
    proof, context = authority._issue_correlation_context(  # type: ignore[attr-defined]
        projection_authority,
        completed,
        expected_predecessor=predecessor,
        active_duplicate=active_duplicate,
    )
    return _ProjectionCase(
        coordinator=coordinator,
        journal=journal,
        completed=completed,
        authority=projection_authority,
        predecessor=predecessor,
        registry=registry,
        proof=proof,
        context=context,
    )


def _assert_mismatch(result: object) -> None:
    assert type(result) is Rejected
    assert result.reason_codes == ("correlation_proof_mismatch",)


def test_projection_authority_issues_exact_context_once_from_real_completed_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    try:
        result = correlate_pcc(case.proof, case.context)

        assert type(result) is CandidateCreated
        assert result.candidate.primary_event_id == (
            case.proof.snapshot.trigger.event_id
        )
        _assert_mismatch(correlate_pcc(case.proof, case.context))
    finally:
        case.close()


def test_new_context_issuance_revokes_every_older_outstanding_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()
    try:
        newest_proof, newest_context = authority._issue_correlation_context(  # type: ignore[attr-defined]
            case.authority,
            case.completed,
            expected_predecessor=case.predecessor,
            active_duplicate=None,
        )

        with pytest.raises(CorrelationProjectionError):
            correlate_pcc(case.proof, case.context)
        assert type(correlate_pcc(newest_proof, newest_context)) is CandidateCreated
    finally:
        case.close()


def test_projection_authority_derives_history_and_lookup_key_without_caller_facts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _authority_module()
    case = _projection_case(tmp_path, monkeypatch)
    try:
        signature = inspect.signature(authority._issue_correlation_context)  # type: ignore[attr-defined]
        assert "coverage" not in signature.parameters
        assert "lookup_key" not in signature.parameters
        path = case.coordinator.segment_store._historical_path_authority(case.proof)
        historical = importlib.import_module(
            "agmind_immune.coverage.historical"
        )
        derived = historical.derive_historical_coverage(case.proof, path)

        assert case.context.coverage == derived
        assert case.context.lookup_key == _duplicate_key(case.proof)
        assert case.context.terminal_observation is None
    finally:
        case.close()


def test_projection_authority_rejects_mismatched_active_duplicate_at_issue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path / "seed", monkeypatch)
    try:
        key = _duplicate_key(case.proof)
        mismatched_key = CandidateDuplicateKey(
            host_id=key.host_id,
            boot_id=key.boot_id,
            docker_container_id=key.docker_container_id,
            docker_started_at=key.docker_started_at,
            detector_bundle_sha256=key.detector_bundle_sha256,
            destination_ipv4="1.1.1.1",
        )
        active = ActiveCandidateObservation(
            key=mismatched_key,
            candidate_id="cand_" + "a" * 64,
            primary_source_sequence=case.proof.source_sequence,
            primary_event_id=case.proof.event_id,
        )

        with pytest.raises(CorrelationProjectionError):
            _authority_module()._issue_correlation_context(  # type: ignore[attr-defined]
                case.authority,
                case.completed,
                expected_predecessor=case.predecessor,
                active_duplicate=active,
            )
    finally:
        case.close()


def test_one_context_raced_by_two_reducers_has_one_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    barrier = Barrier(3)
    results: list[object] = []

    def consume() -> None:
        barrier.wait()
        results.append(correlate_pcc(case.proof, case.context))

    threads = [Thread(target=consume), Thread(target=consume)]
    try:
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()

        assert sum(type(item) is CandidateCreated for item in results) == 1
        assert sum(
            type(item) is Rejected
            and item.reason_codes == ("correlation_proof_mismatch",)
            for item in results
        ) == 1
    finally:
        case.close()


@pytest.mark.parametrize("operation", ["advance", "rebuild", "close"])
def test_kernel_holds_authority_lease_against_state_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    case = _projection_case(tmp_path / operation, monkeypatch)
    pcc_module = importlib.import_module("agmind_immune.correlation.pcc")
    real_kernel = pcc_module._correlate_pcc_kernel
    entered = Event()
    release = Event()
    state_done = Event()
    results: list[object] = []
    state_errors: list[BaseException] = []

    def held_kernel(proof: object, context: object) -> object:
        entered.set()
        assert release.wait(timeout=5)
        return real_kernel(proof, context)

    monkeypatch.setattr(pcc_module, "_correlate_pcc_kernel", held_kernel)

    def consume() -> None:
        results.append(correlate_pcc(case.proof, case.context))

    def change_state() -> None:
        authority = _authority_module()
        try:
            if operation == "advance":
                authority._advance_correlation_projection_authority(  # type: ignore[attr-defined]
                    case.authority,
                    case.predecessor,
                    _present_predecessor(case.proof),
                )
            elif operation == "rebuild":
                authority._rebuild_correlation_projection_authority(  # type: ignore[attr-defined]
                    case.authority,
                    _empty_predecessor(generation=2),
                )
            else:
                authority._close_correlation_projection_authority(  # type: ignore[attr-defined]
                    case.authority
                )
        except BaseException as error:  # noqa: BLE001 - reported in caller thread.
            state_errors.append(error)
        finally:
            state_done.set()

    consumer = Thread(target=consume)
    changer = Thread(target=change_state)
    try:
        consumer.start()
        assert entered.wait(timeout=5)
        changer.start()
        assert not state_done.wait(timeout=0.1)
        release.set()
        consumer.join(timeout=5)
        changer.join(timeout=5)

        assert not consumer.is_alive()
        assert not changer.is_alive()
        assert state_errors == []
        assert len(results) == 1
        assert type(results[0]) is CandidateCreated
    finally:
        release.set()
        case.close()


def test_private_kernel_uses_deep_detached_proof_context_and_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    pcc_module = importlib.import_module("agmind_immune.correlation.pcc")
    real_kernel = pcc_module._correlate_pcc_kernel
    public_trigger = case.proof.snapshot.trigger
    public_coverage = case.context.coverage
    public_registry = case.context.special_use_registry
    assert public_coverage is not None
    assert public_registry is not None
    original_destination = public_trigger.destination_ipv4
    original_critical = public_coverage.critical_gap
    original_index = public_registry._index

    def mutate_restore_kernel(
        trusted_proof: AuthenticatedPCCInput,
        trusted_context: CorrelationContext,
    ) -> object:
        assert trusted_proof is not case.proof
        assert trusted_proof.snapshot is not case.proof.snapshot
        assert trusted_proof.snapshot.trigger is not public_trigger
        assert trusted_context is not case.context
        assert trusted_context.coverage is not public_coverage
        assert trusted_context.lookup_key is not case.context.lookup_key
        assert trusted_context.special_use_registry is not public_registry
        try:
            object.__setattr__(public_trigger, "destination_ipv4", "192.0.2.1")
            object.__setattr__(public_coverage, "critical_gap", True)
            object.__setattr__(
                public_registry,
                "_index",
                (
                    (
                        int(IPv4Address("8.8.8.0")),
                        24,
                        GlobalReachability.FALSE,
                    ),
                ),
            )
            return real_kernel(trusted_proof, trusted_context)
        finally:
            object.__setattr__(public_trigger, "destination_ipv4", original_destination)
            object.__setattr__(public_coverage, "critical_gap", original_critical)
            object.__setattr__(public_registry, "_index", original_index)

    monkeypatch.setattr(
        pcc_module,
        "_correlate_pcc_kernel",
        mutate_restore_kernel,
    )
    try:
        result = correlate_pcc(case.proof, case.context)

        assert type(result) is CandidateCreated
        assert result.candidate.destination_ipv4 == "8.8.8.8"
        assert result.candidate.destination_port == 443
    finally:
        case.close()


def test_hidden_pcc_evidence_ref_is_detached_under_mutate_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    pcc_module = importlib.import_module("agmind_immune.correlation.pcc")
    real_kernel = pcc_module._correlate_pcc_kernel
    public_ref = cast(EvidenceRef, case.proof.evidence_ref)
    original_event_id = public_ref.event_id

    def mutate_restore_kernel(
        trusted_proof: AuthenticatedPCCInput,
        trusted_context: CorrelationContext,
    ) -> object:
        trusted_ref = cast(EvidenceRef, trusted_proof.evidence_ref)
        assert trusted_ref is not public_ref
        assert trusted_ref == public_ref
        try:
            object.__setattr__(
                public_ref,
                "event_id",
                "00000000-0000-4000-8000-000000000099",
            )
            assert trusted_ref.event_id == original_event_id
            return real_kernel(trusted_proof, trusted_context)
        finally:
            object.__setattr__(public_ref, "event_id", original_event_id)

    monkeypatch.setattr(
        pcc_module,
        "_correlate_pcc_kernel",
        mutate_restore_kernel,
    )
    try:
        assert type(correlate_pcc(case.proof, case.context)) is CandidateCreated
    finally:
        case.close()


def test_layout_compatible_class_swap_probe_burns_issued_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    try:
        object.__setattr__(
            case.context,
            "__class__",
            _LayoutCompatibleCorrelationContext,
        )
        try:
            with pytest.raises(TypeError):
                correlate_pcc(case.proof, case.context)
        finally:
            object.__setattr__(case.context, "__class__", CorrelationContext)

        _assert_mismatch(correlate_pcc(case.proof, case.context))
    finally:
        case.close()


def test_exact_store_lifecycle_allows_only_one_live_authority_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()
    try:
        with pytest.raises(CorrelationProjectionError, match="owner"):
            authority._create_correlation_projection_authority(  # type: ignore[attr-defined]
                case.coordinator.segment_store,
                case.registry,
                case.predecessor,
            )
    finally:
        case.close()


def test_store_lifecycle_owner_releases_on_close_and_garbage_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()
    replacement: object | None = None
    final_owner: object | None = None
    try:
        authority._close_correlation_projection_authority(  # type: ignore[attr-defined]
            case.authority
        )
        abandoned = authority._create_correlation_projection_authority(  # type: ignore[attr-defined]
            case.coordinator.segment_store,
            case.registry,
            case.predecessor,
        )
        abandoned_ref = weakref.ref(abandoned)
        del abandoned
        gc.collect()
        assert abandoned_ref() is None

        replacement = authority._create_correlation_projection_authority(  # type: ignore[attr-defined]
            case.coordinator.segment_store,
            case.registry,
            case.predecessor,
        )
        authority._close_correlation_projection_authority(replacement)  # type: ignore[attr-defined]
        final_owner = authority._create_correlation_projection_authority(  # type: ignore[attr-defined]
            case.coordinator.segment_store,
            case.registry,
            case.predecessor,
        )
    finally:
        if final_owner is not None:
            authority._close_correlation_projection_authority(final_owner)  # type: ignore[attr-defined]
        if replacement is not None:
            authority._close_correlation_projection_authority(replacement)  # type: ignore[attr-defined]
        case.close()


@pytest.mark.parametrize("entrypoint", ["proof", "facts"])
def test_failed_snapshot_race_never_enters_candidate_capable_kernel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    failed_coordinator, failed = _accepted_failed(tmp_path / "failed")
    complete_coordinator, complete = _accepted_complete(
        tmp_path / "complete",
        ttl_seconds=120,
    )
    raw_complete_context = _context(complete)
    pcc_module = importlib.import_module("agmind_immune.correlation.pcc")
    real_is_issued = pcc_module.authenticated_pcc_input_is_issued
    failed_snapshot = failed.snapshot
    failed_trigger = failed_snapshot.trigger
    checks = 0

    def swap_after_kernel_issued_check(value: object) -> bool:
        nonlocal checks
        result = real_is_issued(value)
        if value is failed:
            checks += 1
            if checks == 2:
                object.__setattr__(failed, "_snapshot", complete.snapshot)
        return result

    monkeypatch.setattr(
        pcc_module,
        "authenticated_pcc_input_is_issued",
        swap_after_kernel_issued_check,
    )
    try:
        if entrypoint == "proof":
            result = correlate_pcc(failed, raw_complete_context)
        else:
            result = correlate_pcc_facts(
                failed_trigger,
                failed,
                raw_complete_context,
            )

        assert type(result) is Rejected
        assert result.reason_codes == ("inventory_stale",)
    finally:
        object.__setattr__(failed, "_snapshot", failed_snapshot)
        failed_coordinator.segment_store.close()
        complete_coordinator.segment_store.close()


def test_abandoned_issued_context_is_weakly_released(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()
    try:
        _proof, abandoned = authority._issue_correlation_context(  # type: ignore[attr-defined]
            case.authority,
            case.completed,
            expected_predecessor=case.predecessor,
            active_duplicate=None,
        )
        reference = weakref.ref(abandoned)
        del abandoned
        gc.collect()

        assert reference() is None
    finally:
        case.close()


def test_registration_rejects_transient_mutation_that_would_poison_trusted_clone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    pcc_module = importlib.import_module("agmind_immune.correlation.pcc")
    real_trusted_context = pcc_module._trusted_context

    def transient_poison(context: CorrelationContext) -> CorrelationContext:
        coverage = context.coverage
        assert coverage is not None
        original = coverage.critical_gap
        try:
            object.__setattr__(coverage, "critical_gap", True)
            return real_trusted_context(context)
        finally:
            object.__setattr__(coverage, "critical_gap", original)

    monkeypatch.setattr(pcc_module, "_trusted_context", transient_poison)
    try:
        with pytest.raises((TypeError, CorrelationProjectionError)):
            _authority_module()._issue_correlation_context(  # type: ignore[attr-defined]
                case.authority,
                case.completed,
                expected_predecessor=case.predecessor,
                active_duplicate=None,
            )
    finally:
        case.close()


def test_public_context_is_rechecked_after_authority_evaluator_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()
    real_evaluate = authority._evaluate_issued_context  # type: ignore[attr-defined]
    coverage = case.context.coverage
    assert coverage is not None
    original = coverage.critical_gap

    def mutate_after_evaluate(*args: object, **kwargs: object) -> object:
        result = real_evaluate(*args, **kwargs)
        object.__setattr__(coverage, "critical_gap", True)
        return result

    monkeypatch.setattr(
        authority,
        "_evaluate_issued_context",
        mutate_after_evaluate,
    )
    try:
        _assert_mismatch(correlate_pcc(case.proof, case.context))
    finally:
        object.__setattr__(coverage, "critical_gap", original)
        case.close()


def test_authority_evaluator_cannot_invoke_kernel_callback_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()

    def invoke_twice(
        _owner: object,
        _authority_binding: object,
        _context_binding: object,
        callback: Callable[[], object],
    ) -> object:
        first = callback()
        callback()
        return first

    monkeypatch.setattr(
        authority,
        "_evaluate_issued_context",
        invoke_twice,
    )
    try:
        with pytest.raises(CorrelationProjectionError):
            correlate_pcc(case.proof, case.context)
    finally:
        case.close()


@pytest.mark.parametrize("first_api", ["pcc", "facts"])
def test_both_public_reducers_share_the_same_one_use_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    first_api: str,
) -> None:
    case = _projection_case(tmp_path / first_api, monkeypatch)
    try:
        if first_api == "pcc":
            first = correlate_pcc(case.proof, case.context)
            second = correlate_pcc_facts(
                case.proof.snapshot.trigger,
                case.proof,
                case.context,
            )
        else:
            first = correlate_pcc_facts(
                case.proof.snapshot.trigger,
                case.proof,
                case.context,
            )
            second = correlate_pcc(case.proof, case.context)

        assert type(first) is CandidateCreated
        _assert_mismatch(second)
    finally:
        case.close()


def test_raw_equal_and_serialized_contexts_never_gain_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    try:
        raw = _context(case.proof)
        equal = CorrelationContext(
            pinned_detector_bundle_sha256=(
                case.context.pinned_detector_bundle_sha256
            ),
            special_use_registry=case.context.special_use_registry,
            coverage=case.context.coverage,
            lookup_key=case.context.lookup_key,
            active_duplicate=case.context.active_duplicate,
            terminal_observation=case.context.terminal_observation,
        )
        assert equal == case.context
        _assert_mismatch(correlate_pcc(case.proof, raw))
        _assert_mismatch(correlate_pcc(case.proof, equal))

        for copier in (copy.copy, copy.deepcopy):
            with pytest.raises(TypeError):
                copier(case.context)
        with pytest.raises(TypeError):
            pickle.dumps(case.context)

        assert type(correlate_pcc(case.proof, case.context)) is CandidateCreated
    finally:
        case.close()


@pytest.mark.parametrize("probe", ["wrong-trigger", "forged-proof", "cross-proof"])
def test_failed_probe_burns_registered_context_before_public_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe: str,
) -> None:
    case = _projection_case(tmp_path / "primary", monkeypatch)
    other = _projection_case(tmp_path / "other", monkeypatch)
    try:
        if probe == "wrong-trigger":
            with pytest.raises(TypeError):
                correlate_pcc_facts(  # type: ignore[arg-type]
                    object(),
                    case.proof,
                    case.context,
                )
        elif probe == "forged-proof":
            with pytest.raises(TypeError):
                correlate_pcc(  # type: ignore[arg-type]
                    object(),
                    case.context,
                )
        else:
            _assert_mismatch(correlate_pcc(other.proof, case.context))

        _assert_mismatch(correlate_pcc(case.proof, case.context))
    finally:
        case.close()
        other.close()


def test_different_completed_capability_and_proof_cannot_reuse_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()
    try:
        second_completed = case.journal.completed_for_snapshot(
            cast(EvidenceRef, case.proof.evidence_ref)
        )
        second_proof, second_context = authority._issue_correlation_context(  # type: ignore[attr-defined]
            case.authority,
            second_completed,
            expected_predecessor=case.predecessor,
            active_duplicate=None,
        )
        assert second_proof is not case.proof
        assert second_proof.canonical == case.proof.canonical

        _assert_mismatch(correlate_pcc(second_proof, case.context))
        _assert_mismatch(correlate_pcc(case.proof, case.context))
        assert type(correlate_pcc(second_proof, second_context)) is CandidateCreated
    finally:
        case.close()


def test_byte_identical_clone_store_has_no_cross_lifecycle_context_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "source"
    clone_path = tmp_path / "clone"
    case = _projection_case(source_path, monkeypatch)
    clone_store: SegmentStore | None = None
    clone_journal: CorrelationRequestJournal | None = None
    try:
        shutil.copytree(source_path, clone_path)
        clone_store = SegmentStore(clone_path)
        AcceptanceCoordinator.open_and_recover(_fresh_verifier(), clone_store)
        clone_journal = CorrelationRequestJournal.open_and_recover(clone_store)
        clone_completed = clone_journal.completed_for_snapshot(
            cast(EvidenceRef, case.proof.evidence_ref)
        )
        authority = _authority_module()
        predecessor = _empty_predecessor()
        clone_authority = authority._create_correlation_projection_authority(  # type: ignore[attr-defined]
            clone_store,
            load_pinned_special_use_registry(_REGISTRY_PATH),
            predecessor,
        )
        clone_proof, _clone_context = authority._issue_correlation_context(  # type: ignore[attr-defined]
            clone_authority,
            clone_completed,
            expected_predecessor=predecessor,
            active_duplicate=None,
        )
        assert clone_proof.canonical == case.proof.canonical
        assert clone_proof.evidence_ref == case.proof.evidence_ref

        _assert_mismatch(correlate_pcc(clone_proof, case.context))
        _assert_mismatch(correlate_pcc(case.proof, case.context))
    finally:
        if clone_journal is not None:
            clone_journal.close()
        if clone_store is not None:
            clone_store.close()
        case.close()


@pytest.mark.parametrize(
    "revocation",
    [
        "journal-append",
        "journal-rewrite",
        "evidence-advance",
        "predecessor-advance",
        "rebuild",
        "authority-close",
        "store-close",
    ],
)
def test_live_authority_revocation_raises_projection_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    revocation: str,
) -> None:
    case = _projection_case(tmp_path / revocation, monkeypatch)
    authority = _authority_module()
    journal_path = tmp_path / revocation / "correlation-requests.agf"
    try:
        if revocation == "journal-append":
            payloads = read_correlation_frame_payloads(journal_path)
            _append_payload(journal_path, payloads[-1])
        elif revocation == "journal-rewrite":
            raw = journal_path.read_bytes()
            journal_path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        elif revocation == "evidence-advance":
            _accept(
                case.coordinator,
                envelope_value(private_key(11), sequence=4),
            )
        elif revocation == "predecessor-advance":
            authority._advance_correlation_projection_authority(  # type: ignore[attr-defined]
                case.authority,
                case.predecessor,
                _present_predecessor(case.proof),
            )
        elif revocation == "rebuild":
            authority._rebuild_correlation_projection_authority(  # type: ignore[attr-defined]
                case.authority,
                _empty_predecessor(generation=2),
            )
        elif revocation == "authority-close":
            authority._close_correlation_projection_authority(  # type: ignore[attr-defined]
                case.authority
            )
        else:
            case.coordinator.segment_store.close()

        with pytest.raises(CorrelationProjectionError):
            correlate_pcc(case.proof, case.context)
    finally:
        case.close()


@pytest.mark.parametrize("loader_change", ["different", "failure"])
def test_detector_loader_change_or_failure_revokes_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    loader_change: str,
) -> None:
    case = _projection_case(tmp_path / loader_change, monkeypatch)
    authority = _authority_module()

    def unavailable() -> str:
        raise OSError("detector unavailable")

    monkeypatch.setattr(
        authority,
        "_load_pinned_detector_bundle",
        (lambda: "2" * 64) if loader_change == "different" else unavailable,
    )
    try:
        with pytest.raises(CorrelationProjectionError):
            correlate_pcc(case.proof, case.context)
    finally:
        case.close()


def test_registry_policy_mutation_is_live_authority_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    registry = case.context.special_use_registry
    assert registry is not None
    original = registry.entries
    try:
        object.__setattr__(registry, "entries", original[:-1])
        with pytest.raises(CorrelationProjectionError):
            correlate_pcc(case.proof, case.context)
    finally:
        object.__setattr__(registry, "entries", original)
        case.close()


@pytest.mark.parametrize(
    "mutation",
    [
        "registry-replacement",
        "coverage",
        "lookup-key",
        "duplicate",
        "terminal",
        "proof-canonical",
        "proof-request",
        "proof-ref",
    ],
)
def test_context_and_proof_mutation_is_caught_and_burns_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    case = _projection_case(tmp_path / mutation, monkeypatch)
    restore: tuple[object, str, object] | None = None
    try:
        if mutation == "registry-replacement":
            restore = (
                case.context,
                "special_use_registry",
                case.context.special_use_registry,
            )
            object.__setattr__(
                case.context,
                "special_use_registry",
                load_pinned_special_use_registry(_REGISTRY_PATH),
            )
        elif mutation == "coverage":
            coverage = case.context.coverage
            assert coverage is not None
            restore = (coverage, "critical_gap", coverage.critical_gap)
            object.__setattr__(coverage, "critical_gap", True)
        elif mutation == "lookup-key":
            key = cast(CandidateDuplicateKey, case.context.lookup_key)
            restore = (case.context, "lookup_key", key)
            object.__setattr__(
                case.context,
                "lookup_key",
                CandidateDuplicateKey(
                    host_id=key.host_id,
                    boot_id=key.boot_id,
                    docker_container_id=key.docker_container_id,
                    docker_started_at=key.docker_started_at,
                    detector_bundle_sha256=key.detector_bundle_sha256,
                    destination_ipv4="1.1.1.1",
                ),
            )
        elif mutation == "duplicate":
            key = cast(CandidateDuplicateKey, case.context.lookup_key)
            restore = (case.context, "active_duplicate", None)
            object.__setattr__(
                case.context,
                "active_duplicate",
                ActiveCandidateObservation(
                    key=key,
                    candidate_id=candidate_id(
                        case.proof.snapshot.trigger.event_id,
                        key.docker_container_id,
                        key.docker_started_at,
                        key.destination_ipv4,
                        key.detector_bundle_sha256,
                    ),
                    primary_source_sequence=(
                        case.proof.snapshot.trigger.source_sequence
                    ),
                    primary_event_id=case.proof.snapshot.trigger.event_id,
                ),
            )
        elif mutation == "terminal":
            key = cast(CandidateDuplicateKey, case.context.lookup_key)
            restore = (case.context, "terminal_observation", None)
            object.__setattr__(
                case.context,
                "terminal_observation",
                TerminalCandidateObservation(
                    key=key,
                    candidate_id="cand_" + "a" * 64,
                    state="VERIFIED",
                    terminal_at="2026-07-28T09:00:00Z",
                ),
            )
        elif mutation == "proof-canonical":
            restore = (case.proof, "_canonical", case.proof.canonical)
            object.__setattr__(case.proof, "_canonical", b"{}")
        elif mutation == "proof-request":
            request = case.proof.request
            restore = (
                request,
                "requested_ttl_seconds",
                request.requested_ttl_seconds,
            )
            object.__setattr__(request, "requested_ttl_seconds", 30)
        else:
            restore = (case.proof, "_evidence_ref", case.proof.evidence_ref)
            object.__setattr__(case.proof, "_evidence_ref", object())

        try:
            result = correlate_pcc(case.proof, case.context)
        except (TypeError, CorrelationProjectionError):
            result = None
        if result is not None:
            _assert_mismatch(result)
    finally:
        if restore is not None:
            object.__setattr__(*restore)
        try:
            _assert_mismatch(correlate_pcc(case.proof, case.context))
        finally:
            case.close()


def test_predecessor_clock_is_forward_monotonic_generation_fresh_and_aba_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()
    first = _present_predecessor(case.proof)
    second = _present_predecessor(
        case.proof,
        source_sequence=case.proof.source_sequence + 1,
    )
    rebuilt = _empty_predecessor(generation=2)
    try:
        authority._advance_correlation_projection_authority(  # type: ignore[attr-defined]
            case.authority,
            case.predecessor,
            first,
        )
        with pytest.raises(CorrelationProjectionError):
            authority._advance_correlation_projection_authority(  # type: ignore[attr-defined]
                case.authority,
                first,
                case.predecessor,
            )
        with pytest.raises(CorrelationProjectionError):
            authority._advance_correlation_projection_authority(  # type: ignore[attr-defined]
                case.authority,
                first,
                first,
            )
        authority._advance_correlation_projection_authority(  # type: ignore[attr-defined]
            case.authority,
            first,
            second,
        )
        authority._rebuild_correlation_projection_authority(  # type: ignore[attr-defined]
            case.authority,
            rebuilt,
        )
        for stale_generation in (
            _empty_predecessor(generation=1),
            rebuilt,
        ):
            with pytest.raises(CorrelationProjectionError):
                authority._rebuild_correlation_projection_authority(  # type: ignore[attr-defined]
                    case.authority,
                    stale_generation,
                )

        with pytest.raises(CorrelationProjectionError):
            correlate_pcc(case.proof, case.context)
    finally:
        case.close()


def test_caller_predecessor_alias_cannot_rewrite_authority_clock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _projection_case(tmp_path, monkeypatch)
    authority = _authority_module()
    successor = _present_predecessor(case.proof)
    try:
        object.__setattr__(case.predecessor, "generation", 99)
        authority._advance_correlation_projection_authority(  # type: ignore[attr-defined]
            case.authority,
            _empty_predecessor(generation=1),
            successor,
        )

        original_sequence = case.proof.source_sequence
        object.__setattr__(successor, "source_sequence", original_sequence + 100)
        authority._advance_correlation_projection_authority(  # type: ignore[attr-defined]
            case.authority,
            _present_predecessor(
                case.proof,
                source_sequence=original_sequence,
            ),
            _present_predecessor(
                case.proof,
                source_sequence=original_sequence + 1,
            ),
        )
        with pytest.raises(CorrelationProjectionError):
            correlate_pcc(case.proof, case.context)
    finally:
        case.close()


def test_authority_is_opaque_factory_only_immutable_and_not_serializable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_module = _authority_module()
    public_module = importlib.import_module("agmind_immune.correlation")
    authority_type = authority_module.CorrelationProjectionAuthority
    assert public_module.CorrelationProjectionAuthority is authority_type
    assert "CorrelationProjectionAuthority" in public_module.__all__
    for forbidden in (
        "create_correlation_projection_authority",
        "issue_correlation_context",
        "register_correlation_context",
        "CORRELATION_CONTEXT_FACTORY",
        "load_pinned_detector_bundle",
    ):
        assert not hasattr(public_module, forbidden)

    with pytest.raises(TypeError):
        authority_type()
    forged = object.__new__(authority_type)
    with pytest.raises(CorrelationProjectionError):
        authority_module._close_correlation_projection_authority(forged)

    case = _projection_case(tmp_path, monkeypatch)
    try:
        with pytest.raises(AttributeError):
            case.authority.anything = object()
        for copier in (copy.copy, copy.deepcopy):
            with pytest.raises(TypeError):
                copier(case.authority)
        with pytest.raises(TypeError):
            pickle.dumps(case.authority)
    finally:
        case.close()
