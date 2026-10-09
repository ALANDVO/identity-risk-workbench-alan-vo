"""Resolve inherited grants while retaining deterministic shortest evidence paths."""
import heapq
from .models import Identity, Resolution, Snapshot

MAX_EFFECTIVE_GRANTS = 200_000


class AnalysisLimit(ValueError):
    pass


def covers(grant: str, requested: str) -> bool:
    """Whether a grant fully covers a requested permission, including wildcards."""
    granted = grant.split(":")
    required = requested.split(":")
    return len(granted) == len(required) == 2 and all(
        a == "*" or a == b for a, b in zip(granted, required)
    )


def resolve(snapshot: Snapshot, identity: Identity) -> Resolution:
    roles = {r.id: r for r in snapshot.roles}
    groups = {g.id: g for g in snapshot.groups}
    queue = []
    origin = ("identity:" + identity.id,)
    for kind, ids in (("role", identity.roles), ("group", identity.groups)):
        for id_ in ids:
            path = (*origin, kind + ":" + id_)
            heapq.heappush(queue, (len(path), path, kind, id_))
    visited = set()
    paths = {}
    permissions = set()
    while queue:
        _, path, kind, id_ = heapq.heappop(queue)
        if (kind, id_) in visited:
            continue
        visited.add((kind, id_))
        if kind == "role":
            role = roles[id_]
            paths[id_] = path
            permissions.update(role.permissions)
            if len(permissions) > MAX_EFFECTIVE_GRANTS:
                raise AnalysisLimit("Identity exceeds effective permission budget")
            links = [("role", child) for child in role.inherits]
        else:
            group = groups[id_]
            links = [("group", child) for child in group.includes]
            links += [("role", child) for child in group.roles]
        for next_kind, child in links:
            if (next_kind, child) not in visited:
                next_path = (*path, next_kind + ":" + child)
                heapq.heappush(queue, (len(next_path), next_path, next_kind, child))
    return Resolution(identity.id, tuple(sorted(paths)), tuple(sorted(permissions)), paths)


def resolve_all(snapshot: Snapshot) -> dict[str, Resolution]:
    result = {}
    count = 0
    for identity in snapshot.identities:
        row = resolve(snapshot, identity)
        count += len(row.roles) + len(row.permissions)
        if count > MAX_EFFECTIVE_GRANTS:
            raise AnalysisLimit("Snapshot exceeds 200,000 effective role and permission grants; split the export")
        result[identity.id] = row
    return result


def grant_evidence(snapshot: Snapshot, resolution: Resolution, requested: str) -> list[dict]:
    roles = {r.id: r for r in snapshot.roles}
    matches = []
    for role_id in resolution.roles:
        for grant in sorted(roles[role_id].permissions):
            if covers(grant, requested):
                matches.append({"grant": grant, "role_id": role_id, "path": list(resolution.paths[role_id])})
    return matches
