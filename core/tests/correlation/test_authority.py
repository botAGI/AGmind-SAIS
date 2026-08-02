from __future__ import annotations

import importlib
import inspect
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from types import ModuleType

import pytest
from agmind_immune.canonicaljson import pcc_detector_bundle_sha256

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_RULE_PATH = "/etc/falco/rules.d/agmind-pcc.yaml"
_PARENTS = ("/", "/etc", "/etc/falco", "/etc/falco/rules.d")
_MAX_RULE_BYTES = 65_536
_PINNED_RULE_HASH = "9adde9efa900af138a8785b7f313582e8e3688e6ec39fd8045c275841b3880cc"


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
