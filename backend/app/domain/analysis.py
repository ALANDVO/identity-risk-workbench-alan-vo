"""Reproducible snapshot risk findings; scores are triage heuristics, not probabilities."""
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from .graph import covers, grant_evidence, resolve_all
from .imports import permission
from .models import Finding, Policy, Snapshot

RULES = {
    "stale": ("medium", 20, "Review inactivity with the owner; disable only after confirming operational impact."),
    "never_used": ("medium", 15, "Confirm whether this account is required; remove unused grants or disable it."),
    "mfa_missing": ("high", 30, "Require MFA for this privileged human account through the identity provider."),
    "mfa_unknown": ("medium", 15, "Obtain reliable MFA enrollment data before deciding this control is absent."),
    "orphan_service": ("high", 25, "Assign an accountable service owner and review credential rotation and grants."),
    "toxic_pair": ("critical", 40, "Separate the conflicting duties; preview every grant path before removing a role."),
    "disabled_grants": ("low", 5, "Review retained grants before re-enabling this account; disabled does not mean deleted."),
    "concentration": ("medium", 15, "Review the unusually broad grant footprint against the account's documented duties."),
}


def validate_policy(policy: Policy):
    for value in policy.privileged_permissions:
        permission(value, "policy.privileged_permissions")
    for pair in policy.toxic_pairs:
        if not isinstance(pair.name, str) or not pair.name.strip() or len(pair.name) > 160:
            raise ValueError("Toxic pair requires a nonempty name up to 160 characters")
        permission(pair.left, "policy.toxic_pairs.left")
        permission(pair.right, "policy.toxic_pairs.right")
        if pair.left == pair.right:
            raise ValueError("Toxic pairs must describe two different permissions")


def analyze(snapshot: Snapshot, policy: Policy | None = None) -> dict:
    policy = policy or Policy()
    validate_policy(policy)
    resolved = resolve_all(snapshot)
    enabled = [i for i in snapshot.identities if i.enabled]
    # Count grants per account, not the union: a shared entitlement counts once per holder.
    total_permissions = sum(len(resolved[i.id].permissions) for i in enabled)
    findings = []
    rows = []

    def add(identity, rule, title, evidence, key=""):
        severity, points, recommendation = RULES[rule]
        stable = json.dumps([identity.id, rule, key], ensure_ascii=False, separators=(",", ":"))
        findings.append(Finding(hashlib.sha256(stable.encode()).hexdigest()[:24], identity.id,
                                rule, severity, points, title, evidence, recommendation))

    for identity in sorted(snapshot.identities, key=lambda i: i.id):
        finding_start = len(findings)
        effective = resolved[identity.id]
        privileged = [p for p in policy.privileged_permissions if any(covers(g, p) for g in effective.permissions)]
        age_days = (snapshot.observed_at - identity.created_at).total_seconds() / 86400
        inactive_days = ((snapshot.observed_at - identity.last_login).total_seconds() / 86400
                         if identity.last_login is not None else None)
        share = len(effective.permissions) / total_permissions if identity.enabled and total_permissions else 0
        if not identity.enabled:
            if effective.roles:
                add(identity, "disabled_grants", "Disabled identity retains role grants",
                    {"role_count": len(effective.roles), "roles": list(effective.roles)})
        else:
            if inactive_days is not None and inactive_days >= policy.stale_days:
                add(identity, "stale", "No recent sign-in activity", {"inactive_days": round(inactive_days, 3),
                    "threshold_days": policy.stale_days, "last_login": identity.last_login.isoformat()})
            if inactive_days is None and age_days >= policy.never_used_grace_days:
                add(identity, "never_used", "No sign-in recorded after the grace period",
                    {"age_days": round(age_days, 3), "threshold_days": policy.never_used_grace_days})
            if identity.kind == "human" and privileged and identity.mfa is not True:
                rule = "mfa_missing" if identity.mfa is False else "mfa_unknown"
                add(identity, rule, "Privileged human account has " + ("no MFA" if identity.mfa is False else "unknown MFA status"),
                    {"privileged_permissions": privileged, "mfa": identity.mfa})
            if identity.kind == "service" and identity.owner is None:
                add(identity, "orphan_service", "Service identity has no accountable owner", {"owner": None})
            for pair in policy.toxic_pairs:
                left = grant_evidence(snapshot, effective, pair.left)
                right = grant_evidence(snapshot, effective, pair.right)
                if left and right:
                    add(identity, "toxic_pair", pair.name, {"left": pair.left, "right": pair.right,
                        "left_grants": left, "right_grants": right}, pair.name)
            if len(enabled) >= policy.minimum_population and share >= policy.concentration_threshold:
                add(identity, "concentration", "High share of effective permission grants",
                    {"share": round(share, 6), "threshold": policy.concentration_threshold,
                     "account_grants": len(effective.permissions), "population_grants": total_permissions,
                     "enabled_population": len(enabled)})
        mine = findings[finding_start:]
        rows.append({"id": identity.id, "display_name": identity.display_name, "kind": identity.kind,
                     "enabled": identity.enabled, "owner": identity.owner, "mfa": identity.mfa,
                     "last_login": identity.last_login.isoformat() if identity.last_login else None,
                     "created_at": identity.created_at.isoformat(), "direct_roles": list(identity.roles),
                     "groups": list(identity.groups), "effective_roles": list(effective.roles),
                     "permissions": list(effective.permissions), "paths": effective.paths,
                     "privileged": bool(privileged), "grant_share": round(share, 6),
                     "risk_score": min(100, sum(f.points for f in mine)), "finding_count": len(mine)})
    counts = Counter(f.severity for f in findings)
    rules = Counter(f.rule for f in findings)
    return {"snapshot_digest": snapshot.digest, "observed_at": snapshot.observed_at.isoformat(),
            "policy": asdict(policy), "identities": rows, "findings": [asdict(f) for f in findings],
            "summary": {"identities": len(rows), "enabled": len(enabled),
                        "privileged": sum(r["privileged"] and r["enabled"] for r in rows),
                        "findings": len(findings), "by_severity": dict(counts), "by_rule": dict(rules),
                        "effective_permission_grants": total_permissions},
            "limitations": ["Export evidence is historical; no live identity provider queries are performed.",
                            "Permissions use service:action grants; deny policies, conditions and resource scopes are not modeled.",
                            "Last sign-in is not proof of service account use or compromise.",
                            "Risk scores are additive triage weights capped at 100, not breach probabilities."]}
