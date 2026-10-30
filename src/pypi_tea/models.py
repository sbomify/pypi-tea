"""Plain records passed between the ingest worker, the store, and the read path."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SbomRecord:
    uuid: str
    path: str
    media_type: str
    sha256: str
    format: str
    valid: bool
    # Only populated on the ingest side; reads fetch content separately.
    content: str | None = None

    @property
    def family(self) -> str:
        return self.format.split("/", 1)[0]


@dataclass
class WheelRecord:
    url: str
    filename: str
    digests: dict[str, str]
    size: int | None
    sboms: list[SbomRecord] = field(default_factory=list)
    attestation: dict[str, Any] | None = None
    # Set when the wheel could not be inspected for a reason retrying won't fix
    # (corrupt archive, too large to download without range support).
    error: str | None = None

    @property
    def has_sbom(self) -> bool:
        return bool(self.sboms)


@dataclass
class ReleaseRecord:
    name: str
    version: str
    created: str | None
    info: dict[str, Any]
    wheels: list[WheelRecord]

    @property
    def has_sbom(self) -> bool:
        return any(w.sboms for w in self.wheels)

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass(frozen=True)
class Entity:
    uuid: str
    kind: str
    name: str
    version: str | None
    wheel_url: str | None
