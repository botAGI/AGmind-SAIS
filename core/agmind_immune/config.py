"""Strict root-owned production configuration for agmind-core."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from agmind_immune.contracts import decode_strict
from agmind_immune.hunter import HunterConfigV1

CORE_CONFIG_PATH = Path("/etc/agmind-sais/core.json")
SPECIAL_USE_REGISTRY_PATH = Path("/usr/share/agmind-sais/ipv4-special-use.csv")
_MAX_CONFIG_BYTES = 16_384


class CoreConfigV1(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal["agmind.core-config.v1"]
    observer_socket: Literal["/run/agmind-sais/observer-core/socket"]
    actuator_socket: Literal["/run/agmind-sais/actuator-intent/socket"]
    evidence_dir: Literal["/var/lib/agmind-sais/core/evidence"]
    projection_db: Literal["/var/lib/agmind-sais/core/projection.sqlite3"]
    observer_trust_root_file: Literal[
        "/etc/agmind-sais/observer-trust-root.json"
    ]
    actuator_public_key_file: Literal[
        "/etc/agmind-sais/public/actuator-ed25519.pub"
    ]
    api_token_file: Literal["/run/secrets/core-api.token"]
    api_bind_host: Literal["0.0.0.0"]
    api_bind_port: Literal[8787]
    opa_url: Literal["http://opa:8181"]
    hunter_config_file: Literal["/etc/agmind-sais/hunter.json"] | None = None

    @property
    def intent_delivery_db(self) -> Path:
        return Path(self.projection_db).parent / "intent-delivery.sqlite3"


def _read_root_owned(path: Path, maximum: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0 or not path.is_absolute():
        raise ValueError("configuration loading requires an absolute nofollow path")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 1 <= before.st_size <= maximum
        ):
            raise ValueError("configuration file is not a protected root-owned file")
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if (
            len(raw) != before.st_size
            or len(raw) > maximum
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ValueError("configuration file changed while loading")
        return raw
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("configuration file is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_core_config(path: Path = CORE_CONFIG_PATH) -> CoreConfigV1:
    if path != CORE_CONFIG_PATH:
        raise ValueError("Core configuration path is not the production path")
    return decode_strict(_read_root_owned(path, _MAX_CONFIG_BYTES), CoreConfigV1, _MAX_CONFIG_BYTES)


def load_hunter_config(path: Path) -> HunterConfigV1:
    if path != Path("/etc/agmind-sais/hunter.json"):
        raise ValueError("Hunter configuration path is not the production path")
    return decode_strict(
        _read_root_owned(path, _MAX_CONFIG_BYTES),
        HunterConfigV1,
        _MAX_CONFIG_BYTES,
    )


__all__ = [
    "CORE_CONFIG_PATH",
    "SPECIAL_USE_REGISTRY_PATH",
    "CoreConfigV1",
    "load_core_config",
    "load_hunter_config",
]
