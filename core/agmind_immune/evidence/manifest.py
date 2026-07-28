"""Canonical immutable segment-manifest and chain-head contracts."""

from __future__ import annotations

import hashlib
import re
from datetime import date, datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import MAX_UINT64, ContractModel

MANIFEST_HASH_DOMAIN = b"AGMIND_SEGMENT_MANIFEST_V1\0"
GENESIS_MANIFEST_SHA256 = "0" * 64
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EVENT = re.compile(r"^evt_[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SEGMENT_PATH = re.compile(
    r"^segments/[0-9]{4}-[0-9]{2}-[0-9]{2}/"
    r"[0-9]{20}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\.agseg$"
)
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)


def segment_manifest_hash(document: object) -> str:
    """Hash every manifest field except ``manifest_sha256`` in the locked domain."""
    if isinstance(document, SegmentManifestV1):
        value = document.model_dump()
    elif isinstance(document, dict):
        value = dict(document)
    else:
        raise TypeError("manifest hash requires a manifest object")
    value.pop("manifest_sha256", None)
    return hashlib.sha256(MANIFEST_HASH_DOMAIN + canonical_json(value)).hexdigest()


class SegmentManifestV1(ContractModel):
    schema_version: Literal["agmind.segment-manifest.v1"]
    segment_id: str
    segment_relative_path: str
    host_id: str
    evidence_priority: Literal["routine", "protected"]
    first_event_id: str
    last_event_id: str
    first_source_sequence: int = Field(ge=1, le=MAX_UINT64)
    last_source_sequence: int = Field(ge=1, le=MAX_UINT64)
    record_count: int = Field(ge=1, le=MAX_UINT64)
    opened_at: str
    closed_at: str
    segment_size_bytes: int = Field(ge=1, le=MAX_UINT64)
    segment_sha256: str
    first_frame_sha256: str
    last_frame_sha256: str
    previous_manifest_sha256: str
    manifest_sha256: str

    @field_validator("segment_id", "host_id")
    @classmethod
    def uuid_is_exact(cls, value: str) -> str:
        if not _UUID4.fullmatch(value):
            raise ValueError("manifest identity must be lowercase UUIDv4")
        return value

    @field_validator("segment_relative_path")
    @classmethod
    def path_is_exact(cls, value: str) -> str:
        if not _SEGMENT_PATH.fullmatch(value):
            raise ValueError("manifest segment path is not canonical")
        components = value.split("/")
        if len(components) != 3:
            raise ValueError("manifest segment path must have exactly three components")
        try:
            parsed_date = date.fromisoformat(components[1])
        except ValueError as error:
            raise ValueError("manifest segment date is not a real calendar date") from error
        if parsed_date.isoformat() != components[1]:
            raise ValueError("manifest segment date is not canonical")
        return value

    @field_validator("first_event_id", "last_event_id")
    @classmethod
    def event_is_exact(cls, value: str) -> str:
        if not _EVENT.fullmatch(value):
            raise ValueError("manifest event ID is invalid")
        return value

    @field_validator(
        "segment_sha256",
        "first_frame_sha256",
        "last_frame_sha256",
        "previous_manifest_sha256",
        "manifest_sha256",
    )
    @classmethod
    def digest_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("manifest digest is invalid")
        return value

    @field_validator("opened_at", "closed_at")
    @classmethod
    def timestamp_is_exact(cls, value: str) -> str:
        if not _TIMESTAMP.fullmatch(value):
            raise ValueError("manifest timestamp is not RFC3339 UTC")
        return value

    @model_validator(mode="after")
    def facts_are_consistent(self) -> SegmentManifestV1:
        if self.last_source_sequence < self.first_source_sequence:
            raise ValueError("manifest source bounds are reversed")
        opened = datetime.fromisoformat(self.opened_at)
        closed = datetime.fromisoformat(self.closed_at)
        if closed < opened:
            raise ValueError("manifest closed_at precedes opened_at")
        if self.segment_id not in self.segment_relative_path:
            raise ValueError("segment path does not contain segment_id")
        expected_name = (
            f"{self.first_source_sequence:020d}-{self.segment_id}.agseg"
        )
        components = self.segment_relative_path.split("/")
        if components[-1] != expected_name:
            raise ValueError("segment filename does not bind first sequence and segment_id")
        if components[1] != self.opened_at[:10]:
            raise ValueError("segment path date does not match opened_at UTC date")
        if segment_manifest_hash(self) != self.manifest_sha256:
            raise ValueError("manifest_sha256 does not match manifest facts")
        return self


class SegmentChainHeadV1(ContractModel):
    schema_version: Literal["agmind.segment-chain-head.v1"]
    head_segment_id: str
    head_manifest_sha256: str
    last_event_id: str
    last_source_sequence: int = Field(ge=1, le=MAX_UINT64)

    @field_validator("head_segment_id")
    @classmethod
    def segment_id_is_exact(cls, value: str) -> str:
        if not _UUID4.fullmatch(value):
            raise ValueError("chain-head segment_id is invalid")
        return value

    @field_validator("head_manifest_sha256")
    @classmethod
    def digest_is_exact(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise ValueError("chain-head manifest digest is invalid")
        return value

    @field_validator("last_event_id")
    @classmethod
    def event_is_exact(cls, value: str) -> str:
        if not _EVENT.fullmatch(value):
            raise ValueError("chain-head event_id is invalid")
        return value


def chain_head_for(manifest: SegmentManifestV1) -> SegmentChainHeadV1:
    return SegmentChainHeadV1(
        schema_version="agmind.segment-chain-head.v1",
        head_segment_id=manifest.segment_id,
        head_manifest_sha256=manifest.manifest_sha256,
        last_event_id=manifest.last_event_id,
        last_source_sequence=manifest.last_source_sequence,
    )
