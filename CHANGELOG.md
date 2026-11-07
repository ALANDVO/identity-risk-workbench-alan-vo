# Changelog

## 1.4.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## 1.3.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## 1.2.0 — 2026-11-04

- Validate remediation plan action values (including `assign_owner`) against control characters, unpaired surrogates, and surrounding whitespace with HTTP 422 before simulating or saving plans.
- Add finding-rule filtering to snapshot investigation so reviewers can isolate identities and findings triggered by a specific risk rule.

## 1.1.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## [Unreleased]

- Validate remediation plan action values (including `assign_owner`) against control characters, unpaired surrogates, and surrounding whitespace with HTTP 422 before simulating or saving plans.
- Add finding-rule filtering to snapshot investigation so reviewers can isolate identities and findings triggered by a specific risk rule.
- Extend remediation action value validation to `remove_role` and `remove_group` actions for consistent defense-in-depth protection against control characters, unpaired surrogates, and surrounding whitespace.

## [1.0.1]

- Reject malformed Unicode, control characters and surrounding whitespace in custom policy names with HTTP 422 before analysis.
- Add API regression cases for invalid labels.

## [1.0.0] - 2026-10-09

## 1.0.0

- Strict identity exports with timestamp, reference, cycle and expansion validation.
- Effective permission evidence, configurable risk rules and immutable remediation previews.
- Versioned finding reviews and independent plan approval.
- OIDC with PKCE, signed identity tokens, server-side sessions, CSRF and role checks.
- React review workspace, safe exports, bounded audit and optional aggregate-only LLM advice.

---

Alan Vo · [alanvo.net](https://alanvo.net)
