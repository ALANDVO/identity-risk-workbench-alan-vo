"""Immutable identity export contracts and explicit analysis policy."""
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Identity:
    id: str
    display_name: str
    kind: str
    enabled: bool
    created_at: datetime
    last_login: datetime | None
    mfa: bool | None
    owner: str | None
    roles: tuple[str, ...]
    groups: tuple[str, ...]


@dataclass(frozen=True)
class Role:
    id: str
    permissions: tuple[str, ...]
    inherits: tuple[str, ...]


@dataclass(frozen=True)
class Group:
    id: str
    roles: tuple[str, ...]
    includes: tuple[str, ...]


@dataclass(frozen=True)
class Snapshot:
    observed_at: datetime
    identities: tuple[Identity, ...]
    roles: tuple[Role, ...]
    groups: tuple[Group, ...]
    digest: str


@dataclass(frozen=True)
class ToxicPair:
    name: str
    left: str
    right: str


@dataclass(frozen=True)
class Policy:
    stale_days: int = 90
    never_used_grace_days: int = 30
    privileged_permissions: tuple[str, ...] = ("identity:*", "admin:*", "*:*")
    toxic_pairs: tuple[ToxicPair, ...] = (
        ToxicPair("Approve own payment", "payments:create", "payments:approve"),
        ToxicPair("Deploy and suppress audit", "deploy:write", "audit:delete"),
    )
    concentration_threshold: float = 0.5
    minimum_population: int = 3

    def __post_init__(self):
        for name in ("stale_days", "never_used_grace_days", "minimum_population"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 3650:
                raise ValueError(f"{name} must be an integer between 1 and 3650")
        if not 0 < self.concentration_threshold <= 1:
            raise ValueError("concentration_threshold must be between 0 and 1")
        if len(self.toxic_pairs) > 30 or len(self.privileged_permissions) > 100:
            raise ValueError("Policy exceeds rule limits")
        names = [pair.name for pair in self.toxic_pairs]
        if len(set(names)) != len(names):
            raise ValueError("Toxic pair names must be unique")


@dataclass(frozen=True)
class Finding:
    id: str
    identity_id: str
    rule: str
    severity: str
    points: int
    title: str
    evidence: dict
    recommendation: str


@dataclass(frozen=True)
class Resolution:
    identity_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    # One shortest grant path per role; a path is evidence, not every possible grant.
    paths: dict[str, tuple[str, ...]] = field(default_factory=dict)
