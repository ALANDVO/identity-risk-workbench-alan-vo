"""Transactional evidence storage, review decisions and non-executing remediation plans."""
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import csv
import io
import json
from pathlib import Path
import sqlite3
import uuid
from app.domain.analysis import analyze
from app.domain.imports import load_snapshot
from app.domain.policy import parse_policy
from app.domain.remediation import preview


class MissingRecord(LookupError):
    pass


class Conflict(ValueError):
    pass


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def dump(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False, separators=(",", ":"))


def clean_note(value, limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"A nonempty note up to {limit} characters is required")
    if any(ord(c) < 32 and c not in "\n\t" or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("Note contains unsupported control characters")
    return value.strip()


class Catalog:
    def __init__(self, path: str, max_snapshots=25):
        if path == ":memory:":
            raise ValueError("Use a file-backed database; each operation owns its connection")
        self.path = str(Path(path).resolve())
        self.max_snapshots = max_snapshots
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS snapshots (
                    id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
                    observed_at TEXT NOT NULL, imported_at TEXT NOT NULL, imported_by TEXT NOT NULL,
                    raw BLOB NOT NULL, analysis TEXT NOT NULL, policy TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS reviews (
                    snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                    finding_id TEXT NOT NULL, decision TEXT NOT NULL, note TEXT NOT NULL,
                    author TEXT NOT NULL, updated_at TEXT NOT NULL, version INTEGER NOT NULL,
                    PRIMARY KEY(snapshot_id, finding_id));
                CREATE TABLE IF NOT EXISTS plans (
                    id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                    title TEXT NOT NULL, actions TEXT NOT NULL, preview TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'proposed', author TEXT NOT NULL, created_at TEXT NOT NULL,
                    reviewed_by TEXT, decision_note TEXT, reviewed_at TEXT, version INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, resource_id TEXT NOT NULL, details TEXT NOT NULL);
            ''')

    @contextmanager
    def connect(self, write=False):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def audit(conn, actor, action, resource, details):
        conn.execute("INSERT INTO audit(at,actor,action,resource_id,details) VALUES(?,?,?,?,?)",
                     (utcnow(), actor, action, resource, dump(details)))
        # Bounded operational history; never represent it as a permanent compliance archive.
        conn.execute("DELETE FROM audit WHERE sequence <= (SELECT COALESCE(MAX(sequence),0)-5000 FROM audit)")

    @staticmethod
    def row(conn, id_):
        row = conn.execute("SELECT * FROM snapshots WHERE id=?", (id_,)).fetchone()
        if row is None:
            raise MissingRecord("Snapshot not found")
        return row

    @staticmethod
    def metadata(row):
        summary = json.loads(row["analysis"])["summary"]
        return {key: row[key] for key in ("id", "digest", "name", "observed_at", "imported_at", "imported_by", "version")} | {"summary": summary}

    def import_snapshot(self, raw: bytes, name: str, actor: str, policy_data=None):
        name = clean_note(name, 160)
        snapshot = load_snapshot(raw)
        policy = parse_policy(policy_data)
        report = analyze(snapshot, policy)
        with self.connect(write=True) as conn:
            existing = conn.execute("SELECT * FROM snapshots WHERE digest=?", (snapshot.digest,)).fetchone()
            if existing:
                if json.loads(existing["policy"]) != asdict_json(policy):
                    raise Conflict("This export already exists with another policy; use the existing evidence and its recorded policy")
                self.audit(conn, actor, "import_replay", existing["id"], {"digest": snapshot.digest})
                return {"snapshot": self.metadata(existing), "replayed": True}
            if conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] >= self.max_snapshots:
                raise Conflict("Snapshot retention limit reached; export and delete an older snapshot first")
            id_ = str(uuid.uuid4())
            conn.execute("INSERT INTO snapshots(id,digest,name,observed_at,imported_at,imported_by,raw,analysis,policy) VALUES(?,?,?,?,?,?,?,?,?)",
                         (id_, snapshot.digest, name, snapshot.observed_at.isoformat(), utcnow(), actor, raw, dump(report), dump(asdict(policy))))
            self.audit(conn, actor, "snapshot_imported", id_, {"digest": snapshot.digest, "summary": report["summary"]})
            return {"snapshot": self.metadata(self.row(conn, id_)), "replayed": False}

    def list_snapshots(self):
        with self.connect() as conn:
            return [self.metadata(row) for row in conn.execute("SELECT * FROM snapshots ORDER BY imported_at DESC,id DESC")]

    def detail(self, id_):
        with self.connect() as conn:
            row = self.row(conn, id_)
            return {"snapshot": self.metadata(row), "analysis": json.loads(row["analysis"]),
                    "reviews": [dict(r) for r in conn.execute("SELECT * FROM reviews WHERE snapshot_id=? ORDER BY finding_id", (id_,))],
                    "plans": [self.plan_row(p) for p in conn.execute("SELECT * FROM plans WHERE snapshot_id=? ORDER BY created_at DESC,id", (id_,))]}

    def decide_finding(self, id_, finding_id, decision, note, expected_version, actor):
        if decision not in ("open", "accepted", "false_positive", "remediated"):
            raise ValueError("Invalid finding decision")
        if type(expected_version) is not int or expected_version < 0:
            raise ValueError("Review version must be a nonnegative integer")
        note = clean_note(note)
        with self.connect(write=True) as conn:
            row = self.row(conn, id_)
            findings = json.loads(row["analysis"])["findings"]
            if finding_id not in {f["id"] for f in findings}:
                raise MissingRecord("Finding not present in this snapshot")
            prior = conn.execute("SELECT * FROM reviews WHERE snapshot_id=? AND finding_id=?", (id_, finding_id)).fetchone()
            actual = prior["version"] if prior else 0
            if actual != expected_version:
                raise Conflict("Review changed; refresh before saving")
            conn.execute("INSERT INTO reviews(snapshot_id,finding_id,decision,note,author,updated_at,version) VALUES(?,?,?,?,?,?,?) ON CONFLICT(snapshot_id,finding_id) DO UPDATE SET decision=excluded.decision,note=excluded.note,author=excluded.author,updated_at=excluded.updated_at,version=excluded.version",
                         (id_, finding_id, decision, note, actor, utcnow(), actual + 1))
            self.audit(conn, actor, "finding_reviewed", id_, {"finding_id": finding_id, "decision": decision, "version": actual + 1})
            return dict(conn.execute("SELECT * FROM reviews WHERE snapshot_id=? AND finding_id=?", (id_, finding_id)).fetchone())

    def preview_plan(self, id_, actions):
        with self.connect() as conn:
            row = self.row(conn, id_)
            return preview(load_snapshot(row["raw"]), actions, parse_policy(json.loads(row["policy"])))

    @staticmethod
    def plan_row(row):
        value = dict(row)
        value["actions"] = json.loads(value["actions"])
        value["preview"] = json.loads(value["preview"])
        return value

    def create_plan(self, id_, title, actions, actor):
        title = clean_note(title, 160)
        with self.connect(write=True) as conn:
            row = self.row(conn, id_)
            if conn.execute("SELECT COUNT(*) FROM plans WHERE snapshot_id=?", (id_,)).fetchone()[0] >= 100:
                raise Conflict("Maximum of 100 plans per snapshot reached")
            result = preview(load_snapshot(row["raw"]), actions, parse_policy(json.loads(row["policy"])))
            plan_id = str(uuid.uuid4())
            conn.execute("INSERT INTO plans(id,snapshot_id,title,actions,preview,author,created_at) VALUES(?,?,?,?,?,?,?)",
                         (plan_id, id_, title, dump(actions), dump(result), actor, utcnow()))
            self.audit(conn, actor, "plan_proposed", plan_id, {"snapshot_id": id_, "action_count": len(actions)})
            return self.plan_row(conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone())

    def decide_plan(self, id_, plan_id, state, note, expected_version, actor):
        if state not in ("approved", "rejected"):
            raise ValueError("Plan decision must be approved or rejected")
        note = clean_note(note)
        if type(expected_version) is not int or expected_version < 1:
            raise ValueError("Plan version must be a positive integer")
        with self.connect(write=True) as conn:
            self.row(conn, id_)
            row = conn.execute("SELECT * FROM plans WHERE id=? AND snapshot_id=?", (plan_id, id_)).fetchone()
            if row is None:
                raise MissingRecord("Plan not found in this snapshot")
            if row["version"] != expected_version or row["state"] != "proposed":
                raise Conflict("Plan already reviewed or changed")
            if row["author"] == actor:
                raise Conflict("A plan requires a different reviewer from its author")
            conn.execute("UPDATE plans SET state=?,reviewed_by=?,decision_note=?,reviewed_at=?,version=version+1 WHERE id=?",
                         (state, actor, note, utcnow(), plan_id))
            self.audit(conn, actor, "plan_" + state, plan_id, {"snapshot_id": id_, "version": expected_version + 1})
            return self.plan_row(conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone())

    def delete_snapshot(self, id_, expected_version, actor):
        if type(expected_version) is not int:
            raise ValueError("Snapshot version must be an integer")
        with self.connect(write=True) as conn:
            row = self.row(conn, id_)
            if row["version"] != expected_version:
                raise Conflict("Snapshot changed; refresh before deletion")
            conn.execute("DELETE FROM snapshots WHERE id=?", (id_,))
            self.audit(conn, actor, "snapshot_deleted", id_, {"digest": row["digest"]})

    def audit_log(self, limit=100, before=None):
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("Audit limit must be between 1 and 500")
        if before is not None and (type(before) is not int or before < 1):
            raise ValueError("Audit cursor must be positive")
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit WHERE sequence < ? ORDER BY sequence DESC LIMIT ?",
                                (before or 2**63 - 1, limit)).fetchall()
            return [dict(row) | {"details": json.loads(row["details"])} for row in rows]

    def export_json(self, id_):
        return dump(self.detail(id_))

    def export_csv(self, id_):
        detail = self.detail(id_)
        people = {i["id"]: i for i in detail["analysis"]["identities"]}
        reviews = {r["finding_id"]: r for r in detail["reviews"]}
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["identity_id", "display_name", "rule", "severity", "title", "decision", "note", "recommendation"])
        for finding in detail["analysis"]["findings"]:
            review = reviews.get(finding["id"], {})
            writer.writerow([csv_cell(v) for v in [finding["identity_id"], people[finding["identity_id"]]["display_name"],
                finding["rule"], finding["severity"], finding["title"], review.get("decision", "open"),
                review.get("note", ""), finding["recommendation"]]])
        return stream.getvalue()


def asdict_json(policy):
    return json.loads(dump(asdict(policy)))


def csv_cell(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text
