"""Side-effect-free remediation simulation over an immutable evidence snapshot."""
from dataclasses import replace
from .analysis import analyze
from .models import Policy, Snapshot


class PlanFailure(ValueError):
    pass


def preview(snapshot: Snapshot, actions: list[dict], policy: Policy | None = None) -> dict:
    if not isinstance(actions, list) or not 1 <= len(actions) <= 100:
        raise PlanFailure("A plan must contain 1 to 100 actions")
    identities = {i.id: i for i in snapshot.identities}
    seen = set()
    normalized = []
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            raise PlanFailure(f"Action {index}: object required")
        kind = action.get("kind")
        if kind not in ("disable", "remove_role", "remove_group", "assign_owner"):
            raise PlanFailure(f"Action {index}: unsupported action")
        allowed = {"kind", "identity_id"} | ({"value"} if kind != "disable" else set())
        if set(action) != allowed:
            raise PlanFailure(f"Action {index}: fields must be {sorted(allowed)}")
        identity_id = action.get("identity_id")
        if not isinstance(identity_id, str) or identity_id not in identities:
            raise PlanFailure(f"Action {index}: unknown identity")
        identity = identities[identity_id]
        value = action.get("value")
        if kind != "disable" and (not isinstance(value, str) or not value.strip() or len(value) > 160):
            raise PlanFailure(f"Action {index}: nonempty value up to 160 characters required")
        key = (identity_id, kind, value)
        if key in seen:
            raise PlanFailure(f"Action {index}: duplicate action")
        seen.add(key)
        if kind == "disable":
            if not identity.enabled:
                raise PlanFailure(f"Action {index}: identity is already disabled")
            identity = replace(identity, enabled=False)
        elif kind == "remove_role":
            if value not in identity.roles:
                raise PlanFailure(f"Action {index}: only directly assigned roles can be removed here")
            identity = replace(identity, roles=tuple(r for r in identity.roles if r != value))
        elif kind == "remove_group":
            if value not in identity.groups:
                raise PlanFailure(f"Action {index}: only direct group memberships can be removed here")
            identity = replace(identity, groups=tuple(g for g in identity.groups if g != value))
        elif kind == "assign_owner":
            if identity.kind != "service":
                raise PlanFailure(f"Action {index}: owner assignment is for service identities")
            if identity.owner == value:
                raise PlanFailure(f"Action {index}: owner is unchanged")
            identity = replace(identity, owner=value)
        else:
            raise PlanFailure(f"Action {index}: unsupported action")
        identities[identity_id] = identity
        normalized.append(dict(action))
    before = analyze(snapshot, policy)
    after = analyze(replace(snapshot, identities=tuple(identities.values())), policy)
    old = {f["id"]: f for f in before["findings"]}
    new = {f["id"]: f for f in after["findings"]}
    changed = sorted({a["identity_id"] for a in normalized})
    old_rows = {r["id"]: r for r in before["identities"]}
    return {"snapshot_digest": snapshot.digest, "actions": normalized,
            "resolved": [old[k] for k in sorted(old.keys() - new.keys())],
            "introduced": [new[k] for k in sorted(new.keys() - old.keys())],
            "remaining": [new[k] for k in sorted(new.keys() & old.keys())],
            "summary_before": before["summary"], "summary_after": after["summary"],
            "affected": [{"identity_id": row["id"], "score_before": old_rows[row["id"]]["risk_score"],
                          "score_after": row["risk_score"], "remaining_roles": row["effective_roles"],
                          "remaining_permissions": row["permissions"]}
                         for row in after["identities"] if row["id"] in changed or row["risk_score"] != old_rows[row["id"]]["risk_score"]],
            "notice": "Simulation only. No source snapshot or identity provider was changed. Recheck alternative inherited grants before executing an approved plan."}
