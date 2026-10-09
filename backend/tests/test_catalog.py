import json
from concurrent.futures import ThreadPoolExecutor
import pytest
from app.services.catalog import Catalog, Conflict, MissingRecord, csv_cell
from app.domain.policy import parse_policy
from test_domain import export


@pytest.fixture
def catalog(tmp_path):
    return Catalog(str(tmp_path / "evidence.db"))


def imported(catalog):
    return catalog.import_snapshot(json.dumps(export()).encode(), "October export", "analyst")["snapshot"]["id"]


def test_duplicate_import_is_replay_and_keeps_policy(catalog):
    raw = json.dumps(export()).encode()
    first = catalog.import_snapshot(raw, "First", "analyst")
    second = catalog.import_snapshot(raw, "Second", "reviewer")
    assert second["replayed"] is True
    assert first["snapshot"]["id"] == second["snapshot"]["id"]
    assert second["snapshot"]["name"] == "First"
    with pytest.raises(Conflict): catalog.import_snapshot(raw, "Third", "analyst", {"stale_days": 60})
    assert len(catalog.list_snapshots()) == 1


def test_review_version_prevents_lost_update(catalog):
    id_ = imported(catalog)
    finding = catalog.detail(id_)["analysis"]["findings"][0]["id"]
    result = catalog.decide_finding(id_, finding, "accepted", "Temporary business exception", 0, "analyst")
    assert result["version"] == 1
    with pytest.raises(Conflict): catalog.decide_finding(id_, finding, "false_positive", "Racing reviewer", 0, "other")
    assert catalog.detail(id_)["reviews"][0]["decision"] == "accepted"
    assert catalog.detail(id_)["analysis"]["findings"]  # Decisions never erase historical evidence.


def test_two_reviewers_cannot_both_overwrite_same_version(catalog):
    id_ = imported(catalog); finding = catalog.detail(id_)["analysis"]["findings"][0]["id"]
    def attempt(actor):
        try:
            catalog.decide_finding(id_, finding, "accepted", "Reviewed evidence", 0, actor)
            return "saved"
        except Conflict:
            return "conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, ["first", "second"])) == ["conflict", "saved"]


def test_review_rejects_foreign_finding(catalog):
    with pytest.raises(MissingRecord): catalog.decide_finding(imported(catalog), "absent", "open", "Investigating", 0, "analyst")


def test_plan_approval_requires_distinct_actor_and_is_final(catalog):
    id_ = imported(catalog)
    plan = catalog.create_plan(id_, "Remove conflicting group", [{"kind": "remove_group", "identity_id": "a", "value": "nested"}], "analyst")
    with pytest.raises(Conflict): catalog.decide_plan(id_, plan["id"], "approved", "Self approval", 1, "analyst")
    approved = catalog.decide_plan(id_, plan["id"], "approved", "Verified with account owner", 1, "reviewer")
    assert approved["state"] == "approved" and approved["version"] == 2
    with pytest.raises(Conflict): catalog.decide_plan(id_, plan["id"], "rejected", "Too late", 2, "reviewer")
    assert "toxic_pair" in {f["rule"] for f in catalog.detail(id_)["analysis"]["findings"]}


def test_invalid_plan_is_atomic(catalog):
    id_ = imported(catalog)
    with pytest.raises(ValueError): catalog.create_plan(id_, "Bad plan", [{"kind": "disable", "identity_id": "absent"}], "analyst")
    assert catalog.detail(id_)["plans"] == []
    assert [e["action"] for e in catalog.audit_log()] == ["snapshot_imported"]


def test_delete_cascades_reviews_and_plans_but_keeps_audit(catalog):
    id_ = imported(catalog)
    catalog.create_plan(id_, "Review disable", [{"kind": "disable", "identity_id": "a"}], "analyst")
    finding = catalog.detail(id_)["analysis"]["findings"][0]["id"]
    catalog.decide_finding(id_, finding, "open", "Needs owner review", 0, "analyst")
    with pytest.raises(Conflict): catalog.delete_snapshot(id_, 2, "admin")
    catalog.delete_snapshot(id_, 1, "admin")
    with pytest.raises(MissingRecord): catalog.detail(id_)
    with catalog.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM plans").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0] == 0
    assert catalog.audit_log()[0]["action"] == "snapshot_deleted"


def test_snapshot_retention_limit(tmp_path):
    catalog = Catalog(str(tmp_path / "limit.db"), max_snapshots=1)
    imported(catalog)
    data = export(); data["identities"][0]["display_name"] = "Changed"
    with pytest.raises(Conflict): catalog.import_snapshot(json.dumps(data).encode(), "Later", "analyst")


def test_csv_is_safe_and_json_preserves_original(catalog):
    data = export(); data["identities"][0]["display_name"] = '=HYPERLINK("https://example.invalid")'
    id_ = catalog.import_snapshot(json.dumps(data).encode(), "Adversarial name", "analyst")["snapshot"]["id"]
    assert "'=HYPERLINK" in catalog.export_csv(id_)
    assert json.loads(catalog.export_json(id_))["analysis"]["identities"][0]["display_name"].startswith("=HYPERLINK")


@pytest.mark.parametrize("value", ["=1", " +1", "\tvalue", "\rvalue", "-1", "@value"])
def test_csv_formula_cells(value):
    assert csv_cell(value).startswith("'")


def test_audit_pagination_has_no_duplicate(catalog):
    imported(catalog)
    for n in range(3):
        with catalog.connect(write=True) as conn: catalog.audit(conn, "tester", "test", str(n), {})
    first = catalog.audit_log(limit=2)
    second = catalog.audit_log(limit=2, before=first[-1]["sequence"])
    assert len({r["sequence"] for r in first + second}) == 4


@pytest.mark.parametrize("value", [{"unknown": 1}, {"toxic_pairs": "bad"}, {"stale_days": "90"},
    {"concentration_threshold": True}, {"privileged_permissions": ["invalid"]},
    {"privileged_permissions": ["x:y", "x:y"]},
    {"toxic_pairs": [{"name": "Same", "left": "x:y", "right": "x:y"}]}])
def test_policy_rejects_ambiguous_input(value):
    with pytest.raises(ValueError): parse_policy(value)
