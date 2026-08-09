"""Quiesced proof export and fail-closed offline causal verification."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, NoReturn, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agmind_immune.actions.actuator_records import (
    ActuatorRecordError,
    ActuatorRecordProjection,
    _intent_from_plan,
)
from agmind_immune.actions.journal import DecisionIntentJournal
from agmind_immune.actions.models import (
    _decode_decision_intent_record,
    _minimum_age_ms,
)
from agmind_immune.canonicaljson import (
    action_id,
    canonical_json,
    pcc_detector_bundle_sha256,
    pcc_management_denylist_sha256,
)
from agmind_immune.contracts import (
    PCC_SPECIAL_USE_REGISTRY_SHA256,
    ObserverTrustRootV1,
    decode_strict,
)
from agmind_immune.correlation.primitives import load_pinned_special_use_registry
from agmind_immune.evidence.frames import JournalCorrupt, decode_frames
from agmind_immune.evidence.projection import (
    _CANDIDATE_ADMISSION_GATE_FACTORY,
    ProjectionCursor,
    ProjectionStore,
)
from agmind_immune.evidence.segments import EvidenceRef, SegmentStore
from agmind_immune.ingest.ack_journal import AckJournal
from agmind_immune.ingest.correlation_journal import CorrelationRequestJournal
from agmind_immune.ingest.envelope import (
    AnchoredPublicKeyChain,
    EnvelopeVerifier,
    PinnedObserverRoot,
)
from agmind_immune.ingest.service import AcceptanceCoordinator
from agmind_immune.policy.client import (
    POLICY_BUNDLE,
    _policy_input_for_candidate,
    _timestamp_ns,
)
from agmind_immune.policy.models import PolicyDecisionV1

_SCHEMA = "agmind.proof-export.v1"
_BUNDLE_DOMAIN = b"AGMIND_PROOF_EXPORT_V1\0"
_ACTION_ID = re.compile(r"^act_[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
_MAX_FILES = 100_000
_MAX_MANIFEST_BYTES = 32 * 1024 * 1024
_MAX_ACTUATOR_BYTES = 64 * 1024 * 1024
_MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
_MAX_ACTUATOR_RECORDS = 65_536
_MAX_ACTUATOR_PAYLOAD = 65_536
_MAX_METADATA_BYTES = 64 * 1024
_MAX_INPUT_BYTES = 1024 * 1024
_SQLITE_HEADER = b"SQLite format 3\x00"
_REQUIRED_PATHS = frozenset(
    {
        "trust/observer-root.json",
        "trust/observer-public-keys.json",
        "trust/actuator-ed25519.pub",
        "inputs/pcc.rego",
        "inputs/agmind-pcc.yaml",
        "inputs/ipv4-special-use.csv",
        "inputs/management-destinations.json",
        "actuator/actions.agf",
        "evidence/decision-intents.agf",
    }
)
_OPTIONAL_MIRROR = "core/actuator-actions.agf"
_FIXED_BUNDLE_LIMITS = {
    "export-manifest.json": _MAX_MANIFEST_BYTES,
    "trust/observer-root.json": 4_096,
    "trust/observer-public-keys.json": _MAX_METADATA_BYTES,
    "trust/actuator-ed25519.pub": 32,
    "inputs/pcc.rego": _MAX_INPUT_BYTES,
    "inputs/agmind-pcc.yaml": _MAX_INPUT_BYTES,
    "inputs/ipv4-special-use.csv": _MAX_INPUT_BYTES,
    "inputs/management-destinations.json": _MAX_INPUT_BYTES,
    "actuator/actions.agf": _MAX_ACTUATOR_BYTES,
    _OPTIONAL_MIRROR: _MAX_ACTUATOR_BYTES,
}


class ProofExportError(RuntimeError):
    """A proof export cannot be constructed or verified exactly."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ExportFileV1(_FrozenModel):
    path: str
    size: int = Field(ge=0, le=_MAX_TOTAL_BYTES)
    sha256: str

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        _safe_relative(value)
        if value == "export-manifest.json":
            raise ValueError("manifest cannot hash itself")
        return value

    @field_validator("sha256")
    @classmethod
    def hash_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("file hash is not lowercase SHA-256")
        return value


class ExportManifestV1(_FrozenModel):
    schema_version: Literal["agmind.proof-export.v1"]
    action_id: str
    files: tuple[ExportFileV1, ...] = Field(max_length=_MAX_FILES - 1)
    bundle_sha256: str

    @field_validator("files", mode="before")
    @classmethod
    def files_are_tuple(cls, value: object) -> object:
        if type(value) not in (list, tuple):
            raise ValueError("manifest files must be an exact array")
        return tuple(cast(list[object] | tuple[object, ...], value))

    @field_validator("action_id")
    @classmethod
    def action_is_exact(cls, value: str) -> str:
        if _ACTION_ID.fullmatch(value) is None:
            raise ValueError("selected action_id is invalid")
        return value

    @field_validator("bundle_sha256")
    @classmethod
    def bundle_hash_is_exact(cls, value: str) -> str:
        if _HEX64.fullmatch(value) is None:
            raise ValueError("bundle_sha256 is invalid")
        return value

    @model_validator(mode="after")
    def manifest_is_canonical(self) -> ExportManifestV1:
        paths = tuple(item.path for item in self.files)
        if paths != tuple(sorted(set(paths))):
            raise ValueError("manifest file paths are not unique and sorted")
        if sum(item.size for item in self.files) > _MAX_TOTAL_BYTES:
            raise ValueError("manifest exceeds the total byte bound")
        if not hmac.compare_digest(self.bundle_sha256, _bundle_sha256(self)):
            raise ValueError("bundle_sha256 does not bind the manifest")
        return self


class _ManagementDenylistV1(_FrozenModel):
    denied_addresses: tuple[str, ...]
    denied_networks: tuple[str, ...]

    @field_validator("denied_addresses", "denied_networks", mode="before")
    @classmethod
    def arrays_are_tuples(cls, value: object) -> object:
        if type(value) not in (list, tuple):
            raise ValueError("denylist values must be exact arrays")
        return tuple(cast(list[object] | tuple[object, ...], value))


@dataclass(frozen=True, slots=True)
class ExportResult:
    action_id: str
    bundle_sha256: str
    file_count: int
    output: str


@dataclass(frozen=True, slots=True)
class VerifyExportReport:
    integrity_verified: Literal[True]
    causal_links_verified: Literal[True]
    bundle_sha256: str
    action_id: str
    candidate_id: str
    intent_id: str
    action_state: str


@dataclass(frozen=True, slots=True)
class _FileFact:
    size: int
    sha256: str
    binding: tuple[int, ...]


@dataclass(slots=True)
class _CopyTracker:
    output: Path
    files: list[ExportFileV1]
    total: int = 0
    max_files: int = _MAX_FILES - 1

    def check_capacity(self, size: int) -> None:
        if (
            type(size) is not int
            or size < 0
            or len(self.files) >= self.max_files
            or self.total + size > _MAX_TOTAL_BYTES
        ):
            raise ProofExportError("proof export exceeds its file or byte bound")

    def write(self, relative: str, raw: bytes) -> None:
        _safe_relative(relative)
        self.check_capacity(len(raw))
        _write_private_file(self.output, relative, raw)
        self.files.append(
            ExportFileV1(
                path=relative,
                size=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
        self.total += len(raw)


def _safe_relative(value: str) -> PurePosixPath:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8", "strict")) > 4096
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError("bundle relative path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError("bundle relative path is not canonical")
    return path


def _bundle_file_maximum(relative: str) -> int:
    """Return the semantic read bound before any bundle file is opened."""
    _safe_relative(relative)
    fixed = _FIXED_BUNDLE_LIMITS.get(relative)
    if fixed is not None:
        return fixed
    if relative.startswith("evidence/"):
        return _MAX_EVIDENCE_FILE_BYTES
    raise ProofExportError("bundle contains an unexpected non-evidence artifact")


def _bundle_directory_allowed(relative: str) -> bool:
    path = _safe_relative(relative)
    if path.parts[0] == "evidence":
        return True
    return len(path.parts) == 1 and path.parts[0] in {
        "actuator",
        "core",
        "inputs",
        "trust",
    }


def _private_directory(info: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def _private_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600
    )


def _exact_absolute(path: Path, label: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(path)) != path
        or "\x00" in str(path)
    ):
        raise ProofExportError(f"{label} must be one normalized absolute path")
    return path


def _binding(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_descriptor(
    descriptor: int,
    before: os.stat_result,
    maximum: int,
    *,
    label: str,
) -> bytes:
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 <= before.st_size <= maximum
    ):
        raise ProofExportError(f"{label} is unsafe, hard-linked, or oversized")
    chunks: list[bytes] = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise ProofExportError(f"{label} was truncated while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ProofExportError(f"{label} grew while reading")
    raw = b"".join(chunks)
    if _binding(os.fstat(descriptor)) != _binding(before):
        raise ProofExportError(f"{label} changed while reading")
    return raw


def _read_regular(path: Path, maximum: int, *, label: str) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise ProofExportError("proof export requires O_NOFOLLOW")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        before = os.fstat(descriptor)
        raw = _read_descriptor(descriptor, before, maximum, label=label)
        named = os.stat(path, follow_symlinks=False)
        if _binding(named) != _binding(before):
            raise ProofExportError(f"{label} path changed while reading")
        return raw
    except ProofExportError:
        raise
    except OSError as error:
        raise ProofExportError(f"{label} is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _ensure_private_directory(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current /= part
        try:
            os.mkdir(current, 0o700)
        except FileExistsError:
            pass
        info = os.stat(current, follow_symlinks=False)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ProofExportError("proof output directory is not owner-only")
    return current


def _write_private_file(root: Path, relative: str, raw: bytes) -> None:
    path = _safe_relative(relative)
    parent = _ensure_private_directory(root, PurePosixPath(*path.parts[:-1]))
    target = parent / path.name
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
            0o600,
        )
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short proof output write")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = os.stat(target, follow_symlinks=False)
        if (
            _binding(opened) != _binding(named)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size != len(raw)
        ):
            raise ProofExportError("proof output file binding is uncertain")
    except ProofExportError:
        raise
    except OSError as error:
        raise ProofExportError(f"cannot write proof output {relative}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _copy_tree(
    source: Path,
    tracker: _CopyTracker,
    destination: str | None,
    *,
    maximum_for: Callable[[str], int] | None = None,
    directory_allowed: Callable[[str], bool] | None = None,
    evidence_file: Callable[[str], bool] | None = None,
    require_private_source: bool = False,
) -> None:
    """Copy one descriptor-bound tree without trusting path re-resolution."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        raise ProofExportError("proof export requires nofollow directory opens")
    output_info = os.stat(tracker.output, follow_symlinks=False)
    if not _private_directory(output_info):
        raise ProofExportError("proof copy output is not owner-only")
    destination_path = (
        PurePosixPath() if destination is None else _safe_relative(destination)
    )

    def copy_directory(
        descriptor: int,
        source_path: Path,
        relative: PurePosixPath,
        before: os.stat_result,
    ) -> None:
        if not stat.S_ISDIR(before.st_mode) or (
            require_private_source and not _private_directory(before)
        ):
            raise ProofExportError(
                f"source tree contains an unsafe directory: {source_path}"
            )
        _ensure_private_directory(tracker.output, relative)
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as error:
            raise ProofExportError("cannot enumerate source tree") from error
        for name in names:
            if name in {"", ".", ".."} or "/" in name or "\x00" in name:
                raise ProofExportError("source tree contains an unsafe name")
            child_relative = relative / name
            child_text = child_relative.as_posix()
            try:
                too_long = len(child_text.encode("utf-8", "strict")) > 4096
            except UnicodeError as error:
                raise ProofExportError("source tree name is not strict UTF-8") from error
            if too_long:
                raise ProofExportError("source tree path exceeds the lexical bound")
            try:
                entry = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise ProofExportError("source tree entry disappeared") from error
            if stat.S_ISDIR(entry.st_mode):
                if directory_allowed is not None and not directory_allowed(child_text):
                    raise ProofExportError(
                        "bundle contains an unexpected non-evidence directory"
                    )
                if require_private_source and not _private_directory(entry):
                    raise ProofExportError(
                        "source tree contains a non-owner-only directory"
                    )
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | nofollow | directory,
                    dir_fd=descriptor,
                )
                try:
                    opened = os.fstat(child)
                    if _binding(opened) != _binding(entry):
                        raise ProofExportError(
                            "source tree directory changed while opening"
                        )
                    copy_directory(
                        child,
                        source_path / name,
                        child_relative,
                        opened,
                    )
                    named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if _binding(named) != _binding(opened):
                        raise ProofExportError(
                            "source tree directory changed while copying"
                        )
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
                raise ProofExportError(
                    "source tree contains a symlink, device, or hard link"
                )
            if require_private_source and not _private_file(entry):
                raise ProofExportError("source tree contains a non-owner-only file")
            maximum = (
                _MAX_EVIDENCE_FILE_BYTES
                if maximum_for is None
                else maximum_for(child_text)
            )
            if (
                type(maximum) is not int
                or not 0 <= maximum <= _MAX_ACTUATOR_BYTES
                or entry.st_size > maximum
            ):
                raise ProofExportError("source tree file exceeds its semantic bound")
            tracker.check_capacity(entry.st_size)
            child = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | nofollow,
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                if _binding(opened) != _binding(entry):
                    raise ProofExportError("source tree file changed while opening")
                if require_private_source and not _private_file(opened):
                    raise ProofExportError(
                        "source tree file lost its owner-only binding"
                    )
                raw = _read_descriptor(
                    child,
                    opened,
                    maximum,
                    label=f"source tree file {child_text}",
                )
                named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if _binding(named) != _binding(opened):
                    raise ProofExportError("source tree file changed while copying")
            finally:
                os.close(child)
            lowered = name.lower()
            is_evidence = (
                child_relative.parts
                and child_relative.parts[0] == "evidence"
                if evidence_file is None
                else evidence_file(child_text)
            )
            if (
                is_evidence
                and (
                    raw.startswith(_SQLITE_HEADER)
                    or lowered.endswith(
                        (".sqlite", ".sqlite3", ".db", "-wal", "-shm")
                    )
                )
            ):
                raise ProofExportError("mutable SQLite authority is forbidden in evidence")
            tracker.write(child_text, raw)
        if _binding(os.fstat(descriptor)) != _binding(before):
            raise ProofExportError("source tree directory changed during copy")

    root_descriptor = -1
    try:
        root_descriptor = os.open(
            source,
            os.O_RDONLY | os.O_CLOEXEC | nofollow | directory,
        )
        root_before = os.fstat(root_descriptor)
        copy_directory(
            root_descriptor,
            source,
            destination_path,
            root_before,
        )
        named = os.stat(source, follow_symlinks=False)
        if _binding(named) != _binding(root_before):
            raise ProofExportError("source tree root changed during copy")
    except ProofExportError:
        raise
    except OSError as error:
        raise ProofExportError("source tree is unavailable") from error
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)


def _bundle_document(
    manifest: ExportManifestV1 | dict[str, object],
) -> dict[str, object]:
    if type(manifest) is ExportManifestV1:
        document = manifest.model_dump(mode="python")
    elif type(manifest) is dict:
        document = dict(manifest)
    else:
        raise TypeError("bundle digest requires one exact manifest")
    document.pop("bundle_sha256", None)
    return document


def _bundle_sha256(manifest: ExportManifestV1 | dict[str, object]) -> str:
    return hashlib.sha256(
        _BUNDLE_DOMAIN + canonical_json(_bundle_document(manifest))
    ).hexdigest()


def export_quiesced(
    *,
    action_id: str,
    output: Path,
    evidence: Path,
    actuator_journal: Path,
    observer_root: Path,
    observer_public_keys: Path,
    actuator_public_key: Path,
    policy: Path,
    detector: Path,
    registry: Path,
    management_denylist: Path,
    core_mirror: Path | None = None,
) -> ExportResult:
    """Copy explicit quiesced authorities into one new owner-only bundle."""
    if _ACTION_ID.fullmatch(action_id) is None:
        raise ProofExportError("selected action_id is invalid")
    paths = {
        "output": output,
        "evidence": evidence,
        "actuator journal": actuator_journal,
        "observer root": observer_root,
        "observer public keys": observer_public_keys,
        "actuator public key": actuator_public_key,
        "policy": policy,
        "detector": detector,
        "registry": registry,
        "management denylist": management_denylist,
    }
    exact = {label: _exact_absolute(path, label) for label, path in paths.items()}
    mirror = None if core_mirror is None else _exact_absolute(core_mirror, "core mirror")
    try:
        evidence_root = exact["evidence"].resolve(strict=True)
        output_parent = exact["output"].parent.resolve(strict=True)
    except OSError as error:
        raise ProofExportError("proof source or output parent is unavailable") from error
    if (
        evidence_root != exact["evidence"]
        or output_parent != exact["output"].parent
        or output_parent == evidence_root
        or evidence_root in output_parent.parents
    ):
        raise ProofExportError(
            "proof output must not traverse or be nested below the evidence root"
        )
    try:
        os.mkdir(exact["output"], 0o700)
    except FileExistsError as error:
        raise ProofExportError("proof output directory must not already exist") from error
    except OSError as error:
        raise ProofExportError("cannot create proof output directory") from error
    output_info = os.stat(exact["output"], follow_symlinks=False)
    if (
        not stat.S_ISDIR(output_info.st_mode)
        or output_info.st_uid != os.geteuid()
        or stat.S_IMODE(output_info.st_mode) != 0o700
    ):
        raise ProofExportError("proof output directory is not owner-only")
    tracker = _CopyTracker(exact["output"], [])

    fixed = (
        ("trust/observer-root.json", exact["observer root"], 4_096),
        ("trust/observer-public-keys.json", exact["observer public keys"], _MAX_METADATA_BYTES),
        ("trust/actuator-ed25519.pub", exact["actuator public key"], 32),
        ("inputs/pcc.rego", exact["policy"], _MAX_INPUT_BYTES),
        ("inputs/agmind-pcc.yaml", exact["detector"], _MAX_INPUT_BYTES),
        ("inputs/ipv4-special-use.csv", exact["registry"], _MAX_INPUT_BYTES),
        (
            "inputs/management-destinations.json",
            exact["management denylist"],
            _MAX_INPUT_BYTES,
        ),
    )
    for relative, source, maximum in fixed:
        raw = _read_regular(source, maximum, label=relative)
        if not raw or (relative.endswith(".pub") and len(raw) != 32):
            raise ProofExportError(f"{relative} is empty or has an inexact size")
        tracker.write(relative, raw)
    _copy_tree(exact["evidence"], tracker, "evidence")
    actions = _read_regular(
        exact["actuator journal"],
        _MAX_ACTUATOR_BYTES,
        label="actuator journal",
    )
    if not actions:
        raise ProofExportError("selected action requires a nonempty actuator journal")
    tracker.write("actuator/actions.agf", actions)
    if mirror is not None:
        tracker.write(
            _OPTIONAL_MIRROR,
            _read_regular(mirror, _MAX_ACTUATOR_BYTES, label="core actuator mirror"),
        )

    ordered = tuple(sorted(tracker.files, key=lambda item: item.path))
    base: dict[str, object] = {
        "schema_version": _SCHEMA,
        "action_id": action_id,
        "files": ordered,
    }
    base["bundle_sha256"] = _bundle_sha256(base)
    manifest = ExportManifestV1.model_validate(base, strict=True)
    raw_manifest = canonical_json(manifest)
    if (
        len(raw_manifest) > _MAX_MANIFEST_BYTES
        or tracker.total + len(raw_manifest) > _MAX_TOTAL_BYTES
    ):
        raise ProofExportError("proof manifest exceeds its byte bound")
    _write_private_file(exact["output"], "export-manifest.json", raw_manifest)
    return ExportResult(
        action_id=manifest.action_id,
        bundle_sha256=manifest.bundle_sha256,
        file_count=len(manifest.files) + 1,
        output=str(exact["output"]),
    )


def _snapshot_bundle(source: Path, temporary_root: Path) -> Path:
    """Take the only descriptor-bound read of an untrusted proof bundle."""
    prefix = "bundle/"

    def logical(relative: str) -> str:
        if not relative.startswith(prefix):
            raise ProofExportError("proof snapshot path escaped its private root")
        return relative.removeprefix(prefix)

    tracker = _CopyTracker(
        temporary_root,
        [],
        max_files=_MAX_FILES,
    )
    _copy_tree(
        source,
        tracker,
        "bundle",
        maximum_for=lambda relative: _bundle_file_maximum(logical(relative)),
        directory_allowed=lambda relative: _bundle_directory_allowed(
            logical(relative)
        ),
        evidence_file=lambda relative: logical(relative).startswith("evidence/"),
        require_private_source=True,
    )
    return temporary_root / "bundle"


def _scan_bundle(bundle: Path) -> tuple[dict[str, _FileFact], dict[str, bytes]]:
    captures = {
        "export-manifest.json",
        "trust/observer-root.json",
        "trust/observer-public-keys.json",
        "trust/actuator-ed25519.pub",
        "inputs/pcc.rego",
        "inputs/agmind-pcc.yaml",
        "inputs/ipv4-special-use.csv",
        "inputs/management-destinations.json",
        "actuator/actions.agf",
        _OPTIONAL_MIRROR,
    }
    facts: dict[str, _FileFact] = {}
    raw_by_path: dict[str, bytes] = {}
    total = 0
    for root, directories, files in os.walk(bundle, topdown=True, followlinks=False):
        root_path = Path(root)
        root_info = os.stat(root_path, follow_symlinks=False)
        if not _private_directory(root_info):
            raise ProofExportError("bundle contains a non-owner-only directory")
        for name in tuple(directories):
            path = root_path / name
            relative = path.relative_to(bundle).as_posix()
            if not _bundle_directory_allowed(relative):
                raise ProofExportError(
                    "bundle contains an unexpected non-evidence directory"
                )
            info = os.stat(path, follow_symlinks=False)
            if not _private_directory(info):
                raise ProofExportError(
                    "bundle contains a symlink or non-owner-only directory"
                )
        for name in files:
            path = root_path / name
            relative = path.relative_to(bundle).as_posix()
            maximum = _bundle_file_maximum(relative)
            before = os.stat(path, follow_symlinks=False)
            if not _private_file(before):
                raise ProofExportError("bundle contains a non-owner-only file")
            raw = _read_regular(path, maximum, label=f"bundle file {relative}")
            after = os.stat(path, follow_symlinks=False)
            if _binding(after) != _binding(before):
                raise ProofExportError("bundle file changed during fact capture")
            if relative.startswith("evidence/") and raw.startswith(_SQLITE_HEADER):
                raise ProofExportError("bundle evidence contains SQLite authority")
            if relative in facts:
                raise ProofExportError("bundle path is duplicated")
            facts[relative] = _FileFact(
                len(raw),
                hashlib.sha256(raw).hexdigest(),
                _binding(after),
            )
            if relative in captures:
                raw_by_path[relative] = raw
            total += len(raw)
            if len(facts) > _MAX_FILES or total > _MAX_TOTAL_BYTES:
                raise ProofExportError("bundle exceeds its file or byte bound")
    return facts, raw_by_path


def _decode_manifest(raw: bytes) -> ExportManifestV1:
    manifest = decode_strict(raw, ExportManifestV1, _MAX_MANIFEST_BYTES)
    if canonical_json(manifest) != raw:
        raise ProofExportError("export manifest is not canonical JSON")
    return manifest


def _validate_manifest(
    manifest: ExportManifestV1,
    facts: dict[str, _FileFact],
) -> None:
    actual = set(facts)
    if "export-manifest.json" not in actual:
        raise ProofExportError("bundle lacks export-manifest.json")
    listed = {item.path for item in manifest.files}
    if listed != actual - {"export-manifest.json"}:
        raise ProofExportError("manifest does not enumerate the exact bundle")
    if not _REQUIRED_PATHS <= listed:
        raise ProofExportError("bundle lacks one required proof artifact")
    allowed = set(_REQUIRED_PATHS) | {_OPTIONAL_MIRROR}
    unexpected = {
        path for path in listed if path not in allowed and not path.startswith("evidence/")
    }
    if unexpected:
        raise ProofExportError("bundle contains an unexpected non-evidence artifact")
    for item in manifest.files:
        fact = facts[item.path]
        if fact.size != item.size or not hmac.compare_digest(fact.sha256, item.sha256):
            raise ProofExportError(f"manifest hash mismatch for {item.path}")


def _verify_actuator(raw: bytes, public_key: bytes) -> ActuatorRecordProjection:
    try:
        decoded = decode_frames(raw, max_frame=_MAX_ACTUATOR_PAYLOAD)
    except (JournalCorrupt, ValueError) as error:
        raise ProofExportError("actuator AGF1 outer chain is corrupt") from error
    if (
        decoded.torn_tail
        or decoded.verified_bytes != len(raw)
        or len(decoded.records) > _MAX_ACTUATOR_RECORDS
    ):
        raise ProofExportError("actuator AGF1 is torn or exceeds its record bound")
    projection = ActuatorRecordProjection(public_key)
    try:
        for record in decoded.records:
            projection.append(record.payload)
    except ActuatorRecordError as error:
        raise ProofExportError("actuator signed inner chain is invalid") from error
    return projection


def _management_hash(raw: bytes) -> str:
    value = decode_strict(raw, _ManagementDenylistV1, _MAX_INPUT_BYTES)
    return pcc_management_denylist_sha256(
        value.denied_networks,
        value.denied_addresses,
    )


def _expected_decision(record: Any) -> PolicyDecisionV1:
    policy_input = record.policy_input
    return PolicyDecisionV1.model_validate(
        {
            "schema_version": "agmind.policy-decision.v1",
            "effect": "manual_approval_required",
            "reason_codes": ("manual_approval_required",),
            "max_ttl_seconds": min(policy_input.requested_ttl_seconds, 120),
            "allowed_evidence_ids": policy_input.evidence_ids,
            "candidate_id": policy_input.candidate_id,
            "candidate_facts_sha256": policy_input.candidate_facts_sha256,
            "policy_input_sha256": policy_input.policy_input_sha256,
            "policy_bundle_version": POLICY_BUNDLE.version,
            "policy_bundle_sha256": POLICY_BUNDLE.sha256,
        },
        strict=True,
    )


def _new_observer_verifier(
    observer_root_raw: bytes,
    metadata: bytes,
) -> EnvelopeVerifier:
    root_contract = decode_strict(observer_root_raw, ObserverTrustRootV1, 4_096)
    root = PinnedObserverRoot._from_validated_contract(root_contract)
    return EnvelopeVerifier(
        root,
        AnchoredPublicKeyChain.from_value(root, metadata),
    )


def _finish_authorities(
    cleanup: list[tuple[str, Callable[[], None]]],
    primary: BaseException | None,
) -> None:
    failures: list[tuple[str, BaseException]] = []
    for label, close in cleanup:
        try:
            close()
        except BaseException as error:  # noqa: BLE001 - preserve primary failure
            failures.append((label, error))
    if primary is not None:
        for label, failure in failures:
            primary.add_note(f"proof {label} cleanup failed: {failure}")
        return
    if failures:
        label, failure = failures[0]
        failure.add_note(f"proof cleanup failed at {label}")
        raise failure


def _recover_committed_decision(
    evidence_path: Path,
    verifier: EnvelopeVerifier,
    intent_id: str,
) -> tuple[Any, Any]:
    """Recover every live authority before trusting one committed decision."""
    store = SegmentStore(evidence_path)
    ack: AckJournal | None = None
    correlations: CorrelationRequestJournal | None = None
    decisions: DecisionIntentJournal | None = None
    primary: BaseException | None = None
    try:
        AcceptanceCoordinator.open_and_recover(verifier, store)
        ack = AckJournal.open_and_recover(store)
        correlations = CorrelationRequestJournal.open_and_recover(store)
        decisions = DecisionIntentJournal.open(store)
        matches = tuple(
            commit for commit in decisions.records() if commit.intent_id == intent_id
        )
        if len(matches) != 1 or matches[0].intent_canonical is None:
            raise ProofExportError(
                "prepared plan does not resolve to one decision intent"
            )
        commit = matches[0]
        record = _decode_decision_intent_record(commit.record_canonical)
        terminal = EvidenceRef(**record.terminal_ref.model_dump(mode="python"))
        store.resolve_authenticated_ref(terminal)
        acknowledged = ack.snapshot()
        if (
            acknowledged.healthy is not True
            or acknowledged.confirmed_through < terminal.source_sequence
        ):
            raise ProofExportError(
                "ordinary ACK recovery does not confirm the decision terminal"
            )
        return commit, record
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup: list[tuple[str, Callable[[], None]]] = []
        if decisions is not None:
            cleanup.append(("decision journal", decisions.close))
        if correlations is not None:
            cleanup.append(("correlation journal", correlations.close))
        if ack is not None:
            cleanup.append(("ACK journal", ack.close))
        cleanup.append(("evidence", lambda: store.close(flush=False)))
        _finish_authorities(cleanup, primary)


def _remove_ack_authority(evidence_path: Path) -> None:
    """Remove exactly the two ACK artifacts from the private replay snapshot."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        raise ProofExportError("historical replay requires nofollow directory opens")
    descriptor = -1
    names = ("ack-journal.agf", "ack-commitment.json")
    try:
        descriptor = os.open(
            evidence_path,
            os.O_RDONLY | os.O_CLOEXEC | nofollow | directory,
        )
        if not _private_directory(os.fstat(descriptor)):
            raise ProofExportError("historical evidence root is not owner-only")
        for name in names:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not _private_file(info):
                raise ProofExportError("historical ACK artifact is unsafe")
        for name in names:
            os.unlink(name, dir_fd=descriptor)
        for name in names:
            try:
                os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ProofExportError("historical ACK artifact survived removal")
    except ProofExportError:
        raise
    except OSError as error:
        raise ProofExportError("cannot isolate the historical ACK prefix") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _historical_candidate(
    *,
    bundle: Path,
    verifier: EnvelopeVerifier,
    record: Any,
) -> tuple[Any, frozenset[str]]:
    """Replay one exact ACK-confirmed evidence prefix through the decision terminal."""
    evidence_path = bundle / "evidence"
    _remove_ack_authority(evidence_path)
    store = SegmentStore(evidence_path)
    ack: AckJournal | None = None
    correlations: CorrelationRequestJournal | None = None
    projection: ProjectionStore | None = None
    primary: BaseException | None = None
    try:
        AcceptanceCoordinator.open_and_recover(verifier, store)
        terminal = EvidenceRef(**record.terminal_ref.model_dump(mode="python"))
        store.resolve_authenticated_ref(terminal)
        authenticated_records = tuple(
            store.iter_authenticated_records(
                after=0,
                through=terminal.source_sequence,
            )
        )
        if not authenticated_records or authenticated_records[-1].ref != terminal:
            raise ProofExportError(
                "decision terminal is not the final authenticated prefix record"
            )
        ack = AckJournal.create_new(store)
        for item in authenticated_records:
            ack.record_pending(item.ref)
            ack.record_confirmed(item.ref)
        acknowledged = ack.snapshot()
        if (
            acknowledged.healthy is not True
            or acknowledged.pending is not None
            or acknowledged.confirmed is None
            or acknowledged.confirmed.sequence != terminal.source_sequence
            or acknowledged.confirmed.event_id != terminal.event_id
            or acknowledged.confirmed.content_sha256 != terminal.content_sha256
        ):
            raise ProofExportError("historical ACK prefix is not exact")
        correlations = CorrelationRequestJournal.open_and_recover(store)
        registry = load_pinned_special_use_registry(
            bundle / "inputs/ipv4-special-use.csv"
        )
        with tempfile.TemporaryDirectory(
            prefix="agmind-proof-projection-"
        ) as temporary:
            temporary_path = Path(temporary)
            os.chmod(temporary_path, 0o700)
            projection = ProjectionStore.open(
                temporary_path / "projection.sqlite3",
                evidence=store,
                acknowledgements=ack,
                correlation_requests=correlations,
                registry=registry,
            )
            projection.rebuild()
            snapshot = projection._issue_candidate_admission_snapshot(
                record.candidate_id,
                _factory=_CANDIDATE_ADMISSION_GATE_FACTORY,
            )
            if snapshot is None:
                raise ProofExportError(
                    "decision candidate is absent from its historical evidence prefix"
                )
            expected_cursor = ProjectionCursor(
                host_id=record.projection_cursor.host_id,
                source_sequence=record.projection_cursor.source_sequence,
                event_id=record.projection_cursor.event_id,
                content_sha256=record.projection_cursor.content_sha256,
                frame_sha256=record.projection_cursor.frame_sha256,
            )
            if (
                snapshot.candidate_facts_sha256
                != record.candidate_facts_sha256
                or snapshot.authority_snapshot_event_id
                != record.authority_snapshot_event_id
                or snapshot.cursor != expected_cursor
                or snapshot.terminal_ref != terminal
                or snapshot.invalidation_event_ids != ()
            ):
                raise ProofExportError(
                    "historical projection differs from the committed decision prefix"
                )
            authenticated_ids = frozenset(
                item.ref.event_id for item in authenticated_records
            )
            if not set(record.policy_input.evidence_ids) <= authenticated_ids:
                raise ProofExportError(
                    "decision evidence IDs are not authenticated by its prefix"
                )
            candidate = snapshot.candidate
            projection.close()
            projection = None
            return candidate, authenticated_ids
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup: list[tuple[str, Callable[[], None]]] = []
        if projection is not None:
            cleanup.append(("projection", projection.close))
        if correlations is not None:
            cleanup.append(("correlation journal", correlations.close))
        if ack is not None:
            cleanup.append(("ACK journal", ack.close))
        cleanup.append(("evidence", lambda: store.close(flush=False)))
        _finish_authorities(cleanup, primary)


def _verify_causal_bundle(
    bundle: Path,
    manifest: ExportManifestV1,
    raw: dict[str, bytes],
    observer_root_raw: bytes,
    actuator_key: bytes,
    baseline_facts: dict[str, _FileFact],
) -> VerifyExportReport:
    metadata = raw["trust/observer-public-keys.json"]
    actuator_raw = raw["actuator/actions.agf"]
    actuator = _verify_actuator(actuator_raw, actuator_key)
    if _OPTIONAL_MIRROR in raw:
        mirror_raw = raw[_OPTIONAL_MIRROR]
        if not actuator_raw.startswith(mirror_raw):
            raise ProofExportError(
                "optional Core mirror is not an actuator journal prefix"
            )
        _verify_actuator(mirror_raw, actuator_key)
    selected = []
    for state in actuator.intents():
        plan = state.prepared_plan
        if plan is not None and action_id(plan.plan_hash) == manifest.action_id:
            selected.append(state)
    if len(selected) != 1 or selected[0].prepared_plan is None:
        raise ProofExportError("selected action does not resolve to one prepared plan")
    action_state = selected[0]
    plan = action_state.prepared_plan
    assert plan is not None
    action_records = tuple(
        record
        for record in actuator.action_records()
        if record.action_id == manifest.action_id
    )
    if (
        not action_records
        or action_records[-1].state != action_state.state
        or any(
            record.plan_id != plan.plan_id or record.plan_hash != plan.plan_hash
            for record in action_records
        )
    ):
        raise ProofExportError("selected action lifecycle does not bind its prepared plan")

    evidence_path = bundle / "evidence"
    commit, record = _recover_committed_decision(
        evidence_path,
        _new_observer_verifier(observer_root_raw, metadata),
        plan.intent_id,
    )
    recovered_facts, _ = _scan_bundle(bundle)
    if recovered_facts != baseline_facts:
        raise ProofExportError("ordinary evidence recovery mutated the proof snapshot")
    candidate, _authenticated_ids = _historical_candidate(
        bundle=bundle,
        verifier=_new_observer_verifier(observer_root_raw, metadata),
        record=record,
    )

    expected_input = _policy_input_for_candidate(
        candidate,
        record.policy_input.evidence_age_ms,
    )
    try:
        minimum_evaluated_age_ms = _minimum_age_ms(
            candidate.created_at,
            record.evaluated_at,
        )
        minimum_committed_age_ms = _minimum_age_ms(
            candidate.created_at,
            plan.created_at,
        )
        evaluated_ns = _timestamp_ns(record.evaluated_at)
        plan_created_ns = _timestamp_ns(plan.created_at)
    except Exception as error:
        raise ProofExportError("decision freshness timestamps are invalid") from error
    recorded_age_ms = record.policy_input.evidence_age_ms
    fresh_age_ms = record.fresh_evidence_age_ms
    if (
        candidate.candidate_id != commit.candidate_id
        or candidate.candidate_id != record.candidate_id
        or record.candidate_created_at != candidate.created_at
        or recorded_age_ms < minimum_evaluated_age_ms
        or fresh_age_ms < recorded_age_ms
        or fresh_age_ms < minimum_committed_age_ms
        or fresh_age_ms > 120_000
        or minimum_committed_age_ms > 120_000
        or evaluated_ns > plan_created_ns
        or record.committed_at != plan.created_at
        or canonical_json(expected_input) != canonical_json(record.policy_input)
        or canonical_json(_expected_decision(record))
        != canonical_json(record.policy_decision)
        or canonical_json(_intent_from_plan(plan)) != commit.intent_canonical
    ):
        raise ProofExportError(
            "candidate, freshness, policy, decision, intent, and plan do not match"
        )

    policy_raw = raw["inputs/pcc.rego"]
    detector_hash = pcc_detector_bundle_sha256(raw["inputs/agmind-pcc.yaml"])
    registry_hash = hashlib.sha256(raw["inputs/ipv4-special-use.csv"]).hexdigest()
    management_hash = _management_hash(
        raw["inputs/management-destinations.json"]
    )
    policy_input = record.policy_input
    if (
        hashlib.sha256(policy_raw).hexdigest() != POLICY_BUNDLE.sha256
        or policy_input.policy_bundle_sha256 != POLICY_BUNDLE.sha256
        or detector_hash != policy_input.detector_bundle_sha256
        or detector_hash != plan.detector_bundle_sha256
        or registry_hash != PCC_SPECIAL_USE_REGISTRY_SHA256
        or registry_hash != policy_input.special_use_registry_sha256
        or registry_hash != plan.special_use_registry_sha256
        or management_hash != policy_input.management_denylist_sha256
        or management_hash != plan.management_denylist_sha256
        or plan.docker_network_snapshot_sha256
        != policy_input.docker_network_snapshot_sha256
    ):
        raise ProofExportError("bundled policy or safety inputs do not bind the action")
    return VerifyExportReport(
        integrity_verified=True,
        causal_links_verified=True,
        bundle_sha256=manifest.bundle_sha256,
        action_id=manifest.action_id,
        candidate_id=candidate.candidate_id,
        intent_id=plan.intent_id,
        action_state=action_records[-1].state,
    )


def verify_export(
    bundle: Path,
    trusted_observer_root: Path,
    trusted_actuator_key: Path,
) -> VerifyExportReport:
    """Verify exact bytes and the full evidence-to-action causal chain offline."""
    bundle = _exact_absolute(bundle, "proof bundle")
    trusted_observer_root = _exact_absolute(
        trusted_observer_root,
        "trusted observer root",
    )
    trusted_actuator_key = _exact_absolute(
        trusted_actuator_key,
        "trusted actuator key",
    )
    with tempfile.TemporaryDirectory(prefix="agmind-proof-snapshot-") as temporary:
        temporary_root = Path(temporary)
        os.chmod(temporary_root, 0o700)
        snapshot = _snapshot_bundle(bundle, temporary_root)
        facts, raw = _scan_bundle(snapshot)
        manifest_raw = raw.get("export-manifest.json")
        if manifest_raw is None:
            raise ProofExportError("bundle manifest is unavailable")
        manifest = _decode_manifest(manifest_raw)
        _validate_manifest(manifest, facts)
        observer_pin = _read_regular(
            trusted_observer_root,
            4_096,
            label="trusted observer root",
        )
        actuator_pin = _read_regular(
            trusted_actuator_key,
            32,
            label="trusted actuator key",
        )
        if len(actuator_pin) != 32:
            raise ProofExportError("trusted actuator key is not raw Ed25519")
        if not hmac.compare_digest(
            observer_pin,
            raw["trust/observer-root.json"],
        ):
            raise ProofExportError(
                "bundled observer root differs from external trust"
            )
        if not hmac.compare_digest(
            actuator_pin,
            raw["trust/actuator-ed25519.pub"],
        ):
            raise ProofExportError(
                "bundled actuator key differs from external trust"
            )
        return _verify_causal_bundle(
            snapshot,
            manifest,
            raw,
            observer_pin,
            actuator_pin,
            facts,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m agmind_immune.proof")
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export-quiesced")
    export.add_argument("--action-id", required=True)
    export.add_argument("--output", required=True, type=Path)
    export.add_argument("--evidence", required=True, type=Path)
    export.add_argument("--actuator-journal", required=True, type=Path)
    export.add_argument("--core-mirror", type=Path)
    export.add_argument("--observer-root", required=True, type=Path)
    export.add_argument("--observer-public-keys", required=True, type=Path)
    export.add_argument("--actuator-public-key", required=True, type=Path)
    export.add_argument("--policy", required=True, type=Path)
    export.add_argument("--detector", required=True, type=Path)
    export.add_argument("--registry", required=True, type=Path)
    export.add_argument("--management-denylist", required=True, type=Path)
    return parser


def _fatal(parser: argparse.ArgumentParser, error: BaseException) -> NoReturn:
    parser.exit(1, f"proof export failed: {error}\n")


def main() -> None:
    parser = _parser()
    arguments = parser.parse_args()
    try:
        result = export_quiesced(
            action_id=arguments.action_id,
            output=arguments.output,
            evidence=arguments.evidence,
            actuator_journal=arguments.actuator_journal,
            core_mirror=arguments.core_mirror,
            observer_root=arguments.observer_root,
            observer_public_keys=arguments.observer_public_keys,
            actuator_public_key=arguments.actuator_public_key,
            policy=arguments.policy,
            detector=arguments.detector,
            registry=arguments.registry,
            management_denylist=arguments.management_denylist,
        )
    except Exception as error:  # noqa: BLE001 - CLI operational boundary
        _fatal(parser, error)
    print(
        json.dumps(
            {
                "action_id": result.action_id,
                "bundle_sha256": result.bundle_sha256,
                "file_count": result.file_count,
                "output": result.output,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
