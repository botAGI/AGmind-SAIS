"""Fail-closed loading of the Core-visible PCC detector bundle."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from agmind_immune.canonicaljson import pcc_detector_bundle_sha256

__all__: tuple[()] = ()

_MAX_DETECTOR_BUNDLE_BYTES = 65_536
_DIRECTORY_COMPONENTS = ("etc", "falco", "rules.d")
_RULE_NAME = "agmind-pcc.yaml"


class _DetectorBundleUnavailable(RuntimeError):
    pass


class _Stat(Protocol):
    st_dev: int
    st_ino: int
    st_mode: int
    st_nlink: int
    st_uid: int
    st_gid: int
    st_size: int
    st_mtime_ns: int
    st_ctime_ns: int


class _Filesystem(Protocol):
    def stat(
        self,
        path: str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> _Stat: ...

    def open(
        self,
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int: ...

    def fstat(self, descriptor: int) -> _Stat: ...

    def read(self, descriptor: int, count: int) -> bytes: ...

    def close(self, descriptor: int) -> None: ...


class _OSFilesystem:
    @staticmethod
    def stat(
        path: str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> _Stat:
        return cast(
            _Stat,
            os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks),
        )

    @staticmethod
    def open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        return os.open(path, flags, mode, dir_fd=dir_fd)

    @staticmethod
    def fstat(descriptor: int) -> _Stat:
        return cast(_Stat, os.fstat(descriptor))

    @staticmethod
    def read(descriptor: int, count: int) -> bytes:
        return os.read(descriptor, count)

    @staticmethod
    def close(descriptor: int) -> None:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _StatBinding:
    device: int
    inode: int
    mode: int
    link_count: int
    owner: int
    group: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _DirectoryBinding:
    parent_descriptor: int | None
    name: str
    descriptor: int
    stat: _StatBinding


def _binding(info: _Stat) -> _StatBinding:
    return _StatBinding(
        device=info.st_dev,
        inode=info.st_ino,
        mode=info.st_mode,
        link_count=info.st_nlink,
        owner=info.st_uid,
        group=info.st_gid,
        size=info.st_size,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _validate_directory(info: _Stat) -> _StatBinding:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink < 1
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise _DetectorBundleUnavailable(
            "detector bundle parent is not a protected root-owned directory"
        )
    return _binding(info)


def _validate_rule(info: _Stat) -> _StatBinding:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o444
        or not 1 <= info.st_size <= _MAX_DETECTOR_BUNDLE_BYTES
    ):
        raise _DetectorBundleUnavailable(
            "detector bundle is not a protected root-owned read-only file"
        )
    return _binding(info)


def _require_same(actual: _StatBinding, expected: _StatBinding) -> None:
    if actual != expected:
        raise _DetectorBundleUnavailable("detector bundle path changed while loading")


def _load_from_filesystem(filesystem: _Filesystem) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        raise _DetectorBundleUnavailable(
            "detector bundle loading requires O_NOFOLLOW and O_DIRECTORY"
        )
    common_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    directory_flags = common_flags | directory

    descriptors: list[int] = []
    directories: list[_DirectoryBinding] = []
    result: str | None = None
    failure: BaseException | None = None
    try:
        named_root = _validate_directory(filesystem.stat("/", follow_symlinks=False))
        root_descriptor = filesystem.open("/", directory_flags)
        descriptors.append(root_descriptor)
        opened_root = _validate_directory(filesystem.fstat(root_descriptor))
        _require_same(opened_root, named_root)
        directories.append(
            _DirectoryBinding(None, "/", root_descriptor, opened_root)
        )

        parent_descriptor = root_descriptor
        for component in _DIRECTORY_COMPONENTS:
            named = _validate_directory(
                filesystem.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            )
            child_descriptor = filesystem.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            descriptors.append(child_descriptor)
            opened = _validate_directory(filesystem.fstat(child_descriptor))
            _require_same(opened, named)
            directories.append(
                _DirectoryBinding(
                    parent_descriptor,
                    component,
                    child_descriptor,
                    opened,
                )
            )
            parent_descriptor = child_descriptor

        named_rule = _validate_rule(
            filesystem.stat(
                _RULE_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        )
        rule_descriptor = filesystem.open(
            _RULE_NAME,
            common_flags,
            dir_fd=parent_descriptor,
        )
        descriptors.append(rule_descriptor)
        opened_rule = _validate_rule(filesystem.fstat(rule_descriptor))
        _require_same(opened_rule, named_rule)

        raw = filesystem.read(rule_descriptor, _MAX_DETECTOR_BUNDLE_BYTES + 1)
        if type(raw) is not bytes:
            raise _DetectorBundleUnavailable("detector bundle read did not return exact bytes")
        if len(raw) != opened_rule.size or not 1 <= len(raw) <= _MAX_DETECTOR_BUNDLE_BYTES:
            raise _DetectorBundleUnavailable(
                "detector bundle read was short, extra, empty, or oversized"
            )

        post_read_rule = _validate_rule(filesystem.fstat(rule_descriptor))
        _require_same(post_read_rule, opened_rule)

        for held in directories:
            if held.parent_descriptor is None:
                final_named = filesystem.stat("/", follow_symlinks=False)
            else:
                final_named = filesystem.stat(
                    held.name,
                    dir_fd=held.parent_descriptor,
                    follow_symlinks=False,
                )
            _require_same(_validate_directory(final_named), held.stat)
            _require_same(
                _validate_directory(filesystem.fstat(held.descriptor)),
                held.stat,
            )

        final_named_rule = _validate_rule(
            filesystem.stat(
                _RULE_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        )
        _require_same(final_named_rule, opened_rule)
        result = pcc_detector_bundle_sha256(raw)
    except BaseException as error:  # noqa: BLE001 - descriptors close before cancellation.
        failure = error

    close_failure: OSError | None = None
    for descriptor in reversed(descriptors):
        try:
            filesystem.close(descriptor)
        except OSError as error:
            if close_failure is None:
                close_failure = error

    if failure is not None:
        if isinstance(failure, _DetectorBundleUnavailable):
            raise failure
        if isinstance(failure, (OSError, OverflowError, TypeError, ValueError)):
            raise _DetectorBundleUnavailable("detector bundle loading failed") from failure
        raise failure
    if close_failure is not None:
        raise _DetectorBundleUnavailable("detector bundle descriptor close failed") from close_failure
    if result is None:
        raise _DetectorBundleUnavailable("detector bundle loading produced no result")
    return result


def _detector_bundle_loader(filesystem: _Filesystem) -> Callable[[], str]:
    """Create the private no-argument loader around one filesystem boundary."""

    def load() -> str:
        return _load_from_filesystem(filesystem)

    return load


_load_pinned_detector_bundle = _detector_bundle_loader(_OSFilesystem())
