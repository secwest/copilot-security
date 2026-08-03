# Draft Contract Checklist

Write three JSON objects, never a bare array. The host replaces deterministic
identity, timestamp, digest, and seal fields, but semantic fields must already
be present.

## `scan-manifest.json`

The top level must contain `documentType`, `schemaVersion`, and a `scan` object.
The `scan` object must contain:

- `id`
- `producer` with `name` and `version`
- `status: "completed"`
- `startedAt` and `completedAt`
- `target` with `kind`, `targetId`, `displayName`, and the coordinates required
  by that kind
- `scope` with `includePaths` and `excludePaths`
- `coverageRef: "coverage.json"`
- `findingsRef: "findings.json"`

Do not write `sealedAt` or `artifacts`; the host owns them.

## `findings.json`

The top level must contain:

```json
{
  "documentType": "copilot-security.findings",
  "schemaVersion": "1.0",
  "scanId": "<exact scan id>",
  "findings": []
}
```

Every finding must include:

- placeholder `findingId`, `occurrenceId`, and `fingerprints` values; the host
  derives and replaces them
- stable lowercase `ruleId` and `identity.anchor`
- `title` and `summary`
- `severity` object with lowercase `level` and rationale
- `confidence` object with lowercase `level` and rationale
- `taxonomy` object with `category` and explicit CWE array
- nonempty `locations` with `path`, `startLine`, optional `endLine`, and role
- `remediation`
- nonempty `validation` object with a source-backed `summary`, `method`,
  `exploitWitness`, `negativeControl`, `evidence`, `counterEvidence`, and
  `remainingUncertainty`; when a meaningful paired control does not exist,
  explain why in `negativeControl` instead of omitting it
- nonempty `attackPath` object with a source-backed `summary`,
  `dataflow.source`, `dataflow.sink`, `dataflow.outcome`,
  `reachability.attacker`, `reachability.entrypoint`,
  `reachability.outcome`, broken controls, and concise `evidenceRefs`
- `codeEvidence` entries with stable ID, label, path, line, code, explanation,
  and an exact `source`, `propagator`, `sink`, `control`, `impact`, or `evidence`
  role; evidence overlapping a canonical source or sink location must use that
  same endpoint role
- `provenance: {"source": "local_plugin"}`

`findings` contains only validated, reachable security defects with a concrete
adverse impact. A mitigated flow, rejected candidate, safe negative control,
documentation note, hardening suggestion, or defense-in-depth observation is
not a finding—keep it in the candidate ledger and coverage rationale. An empty
findings array is the correct result when every candidate is rejected.

Never substitute a single `location`, string severity/confidence, free-standing
description/evidence field, or finding `id` for those canonical objects.

## `coverage.json`

The top level must contain:

```json
{
  "documentType": "copilot-security.coverage",
  "schemaVersion": "1.0",
  "scanId": "<exact scan id>",
  "mode": "<host-selected coverage mode>",
  "completeness": "complete",
  "inventoryStrategy": "repository",
  "includePaths": [],
  "excludePaths": [],
  "surfaces": [],
  "explicitExclusions": [],
  "deferred": []
}
```

Each reviewed file or security surface belongs in `surfaces` with a stable
`id`, human-readable `label`, one of `reported`, `no_issue_found`, `rejected`,
`not_applicable`, or `needs_follow_up`, and `receiptRefs` (which may be empty).
Each receipt reference is the plain repository-relative path of an existing
file under `artifacts/`; do not append `#` record identifiers or line anchors.
For every path in `artifacts/02_discovery/in_scope_files.txt`, include a
surface whose `label` is that exact repository-relative path. The host
reconciles this immutable inventory before sealing: omitted paths become
`needs_follow_up` with partial completeness rather than being silently treated
as reviewed.
Use `partial` completeness and a matching `deferred` record for any unclosed
work. Never write coverage as a bare per-file array.
