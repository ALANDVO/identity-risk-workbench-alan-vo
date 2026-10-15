# Product development plan

Each round completes one feature or repair. Future items are planned, not implemented claims.

## Current round

remediation-owner-validation-and-quick-stage

## Roadmap

### evidence-intake-and-policy — Strict identity export intake and configurable analysis policy

Status: done

Acceptance:
- Reject malformed JSON, duplicate keys/IDs, unknown references, cycles, invalid timestamps, and control characters before storage
- Preview export findings under custom policy thresholds and toxic permission pairs without storing data
- Deduplicate identical export bytes and preserve recorded policy

Implementation: `backend/app/domain/imports.py`, `backend/app/domain/policy.py`, `backend/app/services/catalog.py`, `frontend/src/ImportPanel.tsx`, `frontend/src/PolicyEditor.tsx`

Tests: `backend/tests/test_domain.py`, `backend/tests/test_catalog.py`, `backend/tests/test_api.py`, `frontend/src/workflows.test.tsx`

### grant-resolution-and-risk-triage — Inherited grant path resolution, risk triage, and finding reviews

Status: done

Acceptance:
- Resolve effective roles and permissions with deterministic shortest grant paths across nested groups and role inheritance
- Compute evidence-backed findings for stale accounts, missing/unknown MFA, orphan services, toxic pairs, disabled grants, and concentration
- Record optimistic-versioned finding review decisions and export safe CSV or JSON

Implementation: `backend/app/domain/graph.py`, `backend/app/domain/analysis.py`, `backend/app/services/catalog.py`, `frontend/src/SnapshotView.tsx`, `frontend/src/FindingReview.tsx`

Tests: `backend/tests/test_domain.py`, `backend/tests/test_catalog.py`, `backend/tests/test_api.py`, `frontend/src/workflows.test.tsx`

### remediation-simulation-and-approval — Immutable remediation simulation and two-person plan approval

Status: done

Acceptance:
- Preview non-executing remediation plans over an immutable snapshot copy and report resolved, introduced, and remaining findings
- Enforce independent reviewer approval distinct from the plan author with optimistic version checks

Implementation: `backend/app/domain/remediation.py`, `backend/app/services/catalog.py`, `frontend/src/PlanPanel.tsx`

Tests: `backend/tests/test_domain.py`, `backend/tests/test_catalog.py`, `backend/tests/test_api.py`, `frontend/src/workflows.test.tsx`

### oidc-sessions-audit-and-evaluation — OIDC PKCE authentication, bounded audit log, policy evaluation, and aggregate LLM advice

Status: done

Acceptance:
- Authenticate via OIDC authorization code + PKCE or loopback-only local demo mode with CSRF and role enforcement
- Provide reproducible synthetic stale-account threshold calibration and optional aggregate-only LLM advice with local fallback

Implementation: `backend/app/core/auth.py`, `backend/app/services/advice.py`, `backend/app/services/evaluation.py`, `frontend/src/EvaluationPanel.tsx`, `frontend/src/AuditPanel.tsx`

Tests: `backend/tests/test_oidc.py`, `backend/tests/test_evaluation.py`, `backend/tests/test_api.py`

### remediation-owner-validation-and-quick-stage — Strict remediation action string validation and identity-scoped finding filter

Status: done

Acceptance:
- Reject control characters, unpaired surrogates, and surrounding whitespace in remediation action values (such as assign_owner) consistently with import and policy validation
- Allow reviewers to filter identities by finding rule in SnapshotView so accounts triggering a specific risk rule can be isolated quickly

Implementation: `backend/app/domain/remediation.py`, `frontend/src/SnapshotView.tsx`

Tests: `backend/tests/test_domain.py`, `backend/tests/test_api.py`, `frontend/src/workflows.test.tsx`

