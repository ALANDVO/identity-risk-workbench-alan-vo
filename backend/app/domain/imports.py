"""Strict, bounded JSON export import. Reject ambiguity before storing evidence."""
import hashlib
import json
from datetime import datetime, timezone
from .models import Group, Identity, Role, Snapshot

MAX_BYTES = 5 * 1024 * 1024
MAX_IDENTITIES = 10000
MAX_NODES = 1000
MAX_EDGES = 30000


class ImportFailure(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors[:100]
        super().__init__("; ".join(self.errors))


def timestamp(value, path):
    if not isinstance(value, str):
        raise ImportFailure([f"{path}: expected ISO-8601 timestamp with timezone"])
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ImportFailure([f"{path}: invalid timestamp"]) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ImportFailure([f"{path}: timezone required"])
    return parsed.astimezone(timezone.utc)


def text(value, path, limit=160):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ImportFailure([f"{path}: nonempty string up to {limit} characters required"])
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ImportFailure([f"{path}: control characters and unpaired surrogates not allowed"])
    if value != value.strip():
        raise ImportFailure([f"{path}: surrounding whitespace is ambiguous"])
    return value


def items(value, path, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise ImportFailure([f"{path}: list of at most {limit} entries required"])
    return value


def names(value, path):
    out = tuple(text(v, path) for v in items(value, path, MAX_NODES))
    if len(set(out)) != len(out):
        raise ImportFailure([f"{path}: duplicate entries"])
    return out


def record(value, path, allowed, required):
    if not isinstance(value, dict):
        raise ImportFailure([f"{path}: object required"])
    extra = set(value) - set(allowed)
    missing = set(required) - set(value)
    if extra or missing:
        raise ImportFailure([f"{path}: unknown fields {sorted(extra)}; missing fields {sorted(missing)}"])
    return value


def boolean(value, path):
    if type(value) is not bool:
        raise ImportFailure([f"{path}: boolean required; strings and integers are not booleans"])
    return value


def permission(value, path):
    value = text(value, path)
    parts = value.split(":")
    if len(parts) != 2 or any(not p or ("*" in p and p != "*") for p in parts):
        raise ImportFailure([f"{path}: permission must be service:action; wildcard must occupy a whole segment"])
    return value


def _unique(values, path):
    seen = set()
    for value in values:
        if value.id in seen:
            raise ImportFailure([f"{path}: duplicate id {value.id}"])
        seen.add(value.id)


def _acyclic(nodes, links, path):
    # Iterative topological check avoids recursion limits for deep exports.
    remaining = {key: len(links(value)) for key, value in nodes.items()}
    reverse = {key: [] for key in nodes}
    for key, value in nodes.items():
        for target in links(value):
            if target not in nodes:
                raise ImportFailure([f"{path}.{key}: unknown reference {target}"])
            reverse[target].append(key)
    ready = [key for key, degree in remaining.items() if degree == 0]
    count = 0
    while ready:
        key = ready.pop()
        count += 1
        for parent in reverse[key]:
            remaining[parent] -= 1
            if remaining[parent] == 0:
                ready.append(parent)
    if count != len(nodes):
        raise ImportFailure([f"{path}: inheritance cycle detected"])


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ImportFailure([f"JSON: duplicate key {key}"])
        result[key] = value
    return result


def load_snapshot(raw: bytes) -> Snapshot:
    if len(raw) > MAX_BYTES:
        raise ImportFailure(["Export exceeds 5 MiB"])
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON number")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ImportFailure):
            raise
        raise ImportFailure(["Export must be valid finite UTF-8 JSON"]) from None
    record(data, "export", {"observed_at", "identities", "roles", "groups"}, {"observed_at", "identities", "roles"})
    observed = timestamp(data["observed_at"], "observed_at")
    roles = []
    for i, row in enumerate(items(data["roles"], "roles", MAX_NODES)):
        path = f"roles[{i}]"
        record(row, path, {"id", "permissions", "inherits"}, {"id", "permissions"})
        perms = names(row["permissions"], path + ".permissions")
        roles.append(Role(text(row["id"], path + ".id"), tuple(permission(p, path) for p in perms),
                          names(row.get("inherits", []), path + ".inherits")))
    groups = []
    for i, row in enumerate(items(data.get("groups", []), "groups", MAX_NODES)):
        path = f"groups[{i}]"
        record(row, path, {"id", "roles", "includes"}, {"id", "roles"})
        groups.append(Group(text(row["id"], path + ".id"), names(row["roles"], path + ".roles"),
                            names(row.get("includes", []), path + ".includes")))
    identities = []
    for i, row in enumerate(items(data["identities"], "identities", MAX_IDENTITIES)):
        path = f"identities[{i}]"
        record(row, path, {"id", "display_name", "kind", "enabled", "created_at", "last_login", "mfa", "owner", "roles", "groups"},
               {"id", "display_name", "kind", "enabled", "created_at", "roles", "groups"})
        kind = row["kind"]
        if kind not in ("human", "service"):
            raise ImportFailure([path + ".kind: expected human or service"])
        created = timestamp(row["created_at"], path + ".created_at")
        last = timestamp(row["last_login"], path + ".last_login") if row.get("last_login") is not None else None
        if created > observed or (last is not None and not created <= last <= observed):
            raise ImportFailure([path + ": timestamps must satisfy created_at <= last_login <= observed_at"])
        identities.append(Identity(
            text(row["id"], path + ".id"), text(row["display_name"], path + ".display_name"), kind,
            boolean(row["enabled"], path + ".enabled"), created, last,
            boolean(row["mfa"], path + ".mfa") if row.get("mfa") is not None else None,
            text(row["owner"], path + ".owner") if row.get("owner") is not None else None,
            names(row["roles"], path + ".roles"), names(row["groups"], path + ".groups")))
    for label, values in (("roles", roles), ("groups", groups), ("identities", identities)):
        _unique(values, label)
    role_map = {r.id: r for r in roles}
    group_map = {g.id: g for g in groups}
    edges = sum(len(r.inherits) + len(r.permissions) for r in roles)
    edges += sum(len(g.roles) + len(g.includes) for g in groups)
    edges += sum(len(i.roles) + len(i.groups) for i in identities)
    if edges > MAX_EDGES:
        raise ImportFailure(["Export exceeds 30,000 grants and inheritance edges"])
    _acyclic(role_map, lambda r: r.inherits, "roles")
    _acyclic(group_map, lambda g: g.includes, "groups")
    for row in [*groups, *identities]:
        for role in row.roles:
            if role not in role_map:
                raise ImportFailure([f"{row.id}: unknown role {role}"])
    for identity in identities:
        for group in identity.groups:
            if group not in group_map:
                raise ImportFailure([f"{identity.id}: unknown group {group}"])
    return Snapshot(observed, tuple(identities), tuple(roles), tuple(groups), hashlib.sha256(raw).hexdigest())
