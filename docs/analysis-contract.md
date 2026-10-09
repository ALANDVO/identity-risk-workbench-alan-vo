# Identity risk analysis contract

Exports are evidence snapshots, not live connectors. The analysis uses the supplied `observed_at`
timestamp, never the server clock, so replaying an export produces the same findings. Every
identity identifier, role and group is case-sensitive. Timestamps require explicit offsets.
Malformed data is rejected before storage; strings such as `"false"` are not accepted as booleans.

An export contains `observed_at`, `identities`, `roles`, and optional `groups`. Each role lists
`permissions` and optional inherited role IDs. Each group lists role IDs and optional included
group IDs. An identity has `id`, `display_name`, `kind` (`human` or `service`), `enabled`,
`created_at`, `roles`, `groups`, and optional `last_login`, `mfa`, and `owner`. Missing MFA means
unknown, not absent. Missing login means no login recorded in this export, not proof an identity
was never used. See `examples/identity-export.json` for synthetic input.

Permissions use `service:action`. A wildcard occupies a whole segment and grants every value
in that segment. No deny rules, conditions, resource scope, cross-account trust, session policy,
or provider-specific permission semantics are inferred. Normalize exports with those limitations
in mind. The configured privileged permission requirements are fully covered by a grant, rather
than merely sharing a prefix. For example, `identity:*` covers `identity:write`; the reverse is
false. The default privileged requirements identify broad identity/admin grants and global grants.

Role and group inheritance must be acyclic and all references must exist. Analysis records one
shortest grant path for each effective role, with a deterministic lexicographic tie-break. That
path is evidence of access, not a complete enumeration of all paths. Remediation always resolves
the changed graph again, so alternate grants remain visible.

## Findings and scoring

Enabled accounts are checked for stale sign-in, absence of recorded sign-in after a grace period,
missing or unknown MFA on privileged human accounts, ownerless service identities, configured
toxic permission pairs, and privilege concentration. Disabled accounts receive only a retained
roles finding and are excluded from the concentration denominator and enabled privileged count.

Concentration is the account's unique effective permission strings divided by the sum of these
counts over enabled identities. It is a grant-footprint heuristic: a wildcard is one permission
string, not an estimate of all actions it permits. Defaults require at least three enabled
identities and a share of at least 0.5. Use the explicit privileged and toxic-pair rules to assess
powerful wildcards. Scores sum rule weights and cap at 100. They are triage priorities, not breach
probabilities. Each finding carries its evidence and recommendation.

## Review and remediation

Finding decisions annotate the original analysis; accepting a risk or marking it remediated does
not erase snapshot evidence. Review saves use optimistic versions to prevent lost updates.

Remediation plans remove direct roles, remove direct group membership, disable identities or
assign service owners. They run on an immutable copy. Previews report resolved, introduced and
remaining findings, and changed scores. The source export is never modified. Approval requires a
different authenticated actor from the plan author. Approved plans are still proposals for an
external operator to execute; the application never claims it executed identity-provider changes.

## Storage and limits

The SQLite catalog uses transactions, foreign keys, WAL and a busy timeout. Imports deduplicate
by SHA-256 of the exact uploaded bytes. Importing the same bytes with a different policy is
rejected rather than silently substituting analysis. Policy is recorded with each snapshot.

Imports are limited to 5 MiB, 10,000 identities, 1,000 roles, 1,000 groups and 30,000 declared
permission/inheritance/membership edges. Resolution has a 200,000 effective role/permission grant
budget across the export. Split exports exceeding it. Keep split-population concentration limits
in mind. Storage defaults to 25 snapshots and 100 plans per snapshot. Audit keeps the latest
5,000 events; it is an operational history, not an immutable compliance archive. Deleting a
snapshot cascades its reviews and plans but retains a digest-only deletion audit entry. Back up
and export evidence according to organizational retention requirements.

CSV exports neutralize spreadsheet formula prefixes; JSON preserves the original strings.
The database contains identity information and must be protected by filesystem permissions,
backup access controls and authenticated deployment. Synthetic examples contain no real users.
