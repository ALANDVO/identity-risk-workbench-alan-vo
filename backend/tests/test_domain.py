import copy
import json
from dataclasses import replace
import pytest
from app.domain.imports import ImportFailure, load_snapshot
from app.domain.models import Policy
from app.domain.graph import covers, resolve_all, AnalysisLimit
from app.domain.analysis import analyze
from app.domain.remediation import PlanFailure, preview


def export():
    return {
        "observed_at": "2026-10-01T00:00:00Z",
        "roles": [
            {"id": "pay", "permissions": ["payments:create"]},
            {"id": "approve", "permissions": ["payments:approve"]},
            {"id": "admin", "permissions": ["identity:*"], "inherits": ["pay"]},
        ],
        "groups": [{"id": "finance", "roles": ["approve"], "includes": []},
                   {"id": "nested", "roles": [], "includes": ["finance"]}],
        "identities": [
            {"id": "a", "display_name": "Analyst", "kind": "human", "enabled": True,
             "created_at": "2026-01-01T00:00:00Z", "last_login": "2026-09-30T00:00:00Z",
             "mfa": False, "roles": ["admin"], "groups": ["nested"]},
            {"id": "b", "display_name": "Worker", "kind": "service", "enabled": True,
             "created_at": "2026-01-01T00:00:00Z", "last_login": None,
             "roles": ["pay"], "groups": []},
            {"id": "c", "display_name": "Reviewer", "kind": "human", "enabled": True,
             "created_at": "2026-01-01T00:00:00Z", "last_login": "2026-09-30T00:00:00Z",
             "mfa": True, "roles": ["approve"], "groups": []},
        ],
    }


def snapshot(data=None):
    return load_snapshot(json.dumps(data or export()).encode())


def rules(result, identity):
    return {f["rule"] for f in result["findings"] if f["identity_id"] == identity}


def test_inherited_permissions_and_shortest_paths():
    resolved = resolve_all(snapshot())["a"]
    assert resolved.permissions == ("identity:*", "payments:approve", "payments:create")
    assert resolved.paths["pay"] == ("identity:a", "role:admin", "role:pay")
    assert resolved.paths["approve"] == ("identity:a", "group:nested", "group:finance", "role:approve")


def test_direct_role_wins_over_inherited_path():
    data = export(); data["identities"][0]["roles"].append("pay")
    assert resolve_all(snapshot(data))["a"].paths["pay"] == ("identity:a", "role:pay")


@pytest.mark.parametrize("grant,required,want", [
    ("*:*", "payments:approve", True), ("payments:*", "payments:approve", True),
    ("*:approve", "payments:approve", True), ("payments:approve", "payments:*", False),
    ("payments:read", "payments:approve", False), ("Payments:*", "payments:approve", False),
])
def test_permission_scope(grant, required, want):
    assert covers(grant, required) is want


def test_findings_are_evidenced_and_service_is_not_mfa_checked():
    result = analyze(snapshot())
    assert rules(result, "a") == {"mfa_missing", "toxic_pair", "concentration"}
    assert rules(result, "b") == {"orphan_service", "never_used"}
    toxic = next(f for f in result["findings"] if f["rule"] == "toxic_pair")
    assert toxic["evidence"]["right_grants"][0]["path"][-1] == "role:approve"
    assert result["summary"]["effective_permission_grants"] == 5


def test_unknown_mfa_is_not_missing():
    data = export(); data["identities"][0].pop("mfa")
    assert "mfa_unknown" in rules(analyze(snapshot(data)), "a")
    assert "mfa_missing" not in rules(analyze(snapshot(data)), "a")


def test_disabled_identity_has_only_retained_grants_finding():
    data = export(); data["identities"][0]["enabled"] = False
    result = analyze(snapshot(data))
    assert rules(result, "a") == {"disabled_grants"}
    assert result["summary"]["privileged"] == 0
    assert result["summary"]["effective_permission_grants"] == 2


@pytest.mark.parametrize("days,stale", [(89, False), (90, True), (91, True)])
def test_stale_boundary(days, stale):
    from datetime import timedelta, datetime, timezone
    data = export(); data["identities"][0]["last_login"] = (datetime(2026, 10, 1, tzinfo=timezone.utc) - timedelta(days=days)).isoformat()
    assert ("stale" in rules(analyze(snapshot(data)), "a")) is stale


def test_new_identity_without_login_has_grace_period():
    data = export(); data["identities"][1]["created_at"] = "2026-09-30T00:00:00Z"
    assert "never_used" not in rules(analyze(snapshot(data)), "b")


def test_small_population_does_not_raise_concentration():
    data = export(); data["identities"] = data["identities"][:2]
    assert "concentration" not in rules(analyze(snapshot(data)), "a")


def test_removing_direct_role_does_not_remove_alternate_grant():
    data = export(); data["identities"][0]["roles"].append("approve")
    s = snapshot(data)
    result = preview(s, [{"kind": "remove_role", "identity_id": "a", "value": "approve"}])
    assert any(f["rule"] == "toxic_pair" for f in result["remaining"])
    assert "approve" in result["affected"][0]["remaining_roles"]
    assert "approve" in s.identities[0].roles


def test_removing_group_resolves_toxic_pair_without_mutating_snapshot():
    s = snapshot(); before = analyze(s)
    result = preview(s, [{"kind": "remove_group", "identity_id": "a", "value": "nested"}])
    assert any(f["rule"] == "toxic_pair" for f in result["resolved"])
    assert analyze(s) == before


def test_disable_introduces_retained_grants_finding():
    result = preview(snapshot(), [{"kind": "disable", "identity_id": "a"}])
    assert any(f["rule"] == "disabled_grants" for f in result["introduced"])
    assert result["summary_after"]["enabled"] == 2


def test_assign_service_owner_resolves_orphan():
    result = preview(snapshot(), [{"kind": "assign_owner", "identity_id": "b", "value": "Operations"}])
    assert any(f["rule"] == "orphan_service" for f in result["resolved"])


@pytest.mark.parametrize("actions", [[], [{"kind": "unknown", "identity_id": "a"}],
    [{"kind": {}, "identity_id": "a"}], [{"kind": "disable", "identity_id": "missing"}],
    [{"kind": "remove_role", "identity_id": "a", "value": "pay"}],
    [{"kind": "assign_owner", "identity_id": "a", "value": "Human"}],
    [{"kind": "disable", "identity_id": "a", "value": "extra"}],
    [{"kind": "disable", "identity_id": "a"}] * 2,
])
def test_invalid_plan_is_rejected(actions):
    with pytest.raises(PlanFailure): preview(snapshot(), actions)


@pytest.mark.parametrize("field,value", [("enabled", "false"), ("mfa", 0), ("id", " a"),
    ("kind", "robot"), ("last_login", "2027-01-01T00:00:00Z"),
    ("created_at", "2026-01-01T00:00:00"), ("id", "a\ud800"), ("roles", ["missing"]),
    ("groups", ["missing"]), ("roles", ["admin", "admin"]), ("last_login", "2025-01-01T00:00:00Z")])
def test_invalid_identity_fields(field, value):
    data = export(); data["identities"][0][field] = value
    with pytest.raises(ImportFailure): snapshot(data)


@pytest.mark.parametrize("section", ["roles", "groups", "identities"])
def test_duplicate_ids_rejected(section):
    data = export(); data[section].append(copy.deepcopy(data[section][0]))
    with pytest.raises(ImportFailure, match="duplicate id"): snapshot(data)


@pytest.mark.parametrize("section,edge", [("roles", "inherits"), ("groups", "includes")])
def test_cycles_rejected(section, edge):
    data = export(); data[section][0][edge] = [data[section][0]["id"]]
    with pytest.raises(ImportFailure, match="cycle"): snapshot(data)


@pytest.mark.parametrize("raw", [b'{"roles":[],"roles":[]}', b'NaN', b'\xff', b'[]', b'{}', b'{' * 1200])
def test_bad_json_rejected(raw):
    with pytest.raises(ImportFailure): load_snapshot(raw)


def test_empty_valid_export_is_not_error():
    result = analyze(snapshot({"observed_at": "2026-01-01T00:00:00Z", "identities": [], "roles": []}))
    assert result["summary"]["identities"] == 0
    assert result["findings"] == []


def test_order_does_not_change_findings_or_scores():
    a = export(); b = copy.deepcopy(a)
    for field in ("identities", "roles", "groups"): b[field].reverse()
    assert analyze(snapshot(a))["findings"] == analyze(snapshot(b))["findings"]
    assert analyze(snapshot(a))["identities"] == analyze(snapshot(b))["identities"]


def test_effective_grant_budget(monkeypatch):
    monkeypatch.setattr("app.domain.graph.MAX_EFFECTIVE_GRANTS", 3)
    with pytest.raises(AnalysisLimit): analyze(snapshot())


@pytest.mark.parametrize("kwargs", [{"stale_days": 0}, {"stale_days": True},
    {"concentration_threshold": float("nan")}, {"minimum_population": -1}])
def test_policy_bounds(kwargs):
    with pytest.raises(ValueError): Policy(**kwargs)
