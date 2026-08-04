# Local secret candidate scanning

Copilot Security runs a deterministic secret-candidate pass in the trusted host
before starting a Copilot model session. The pass covers every bounded plaintext
file for repository scans and the immutable host inventory for scoped and diff
scans. It ignores links, binary data, generated dependency/build trees,
oversized files, and paths that escape the registered repository.

The detector currently recognizes high-confidence GitHub, GitLab, Slack,
Stripe, npm, PyPI, SendGrid, Google, and AWS credential forms, private-key
markers, and quoted or dotenv-style high-entropy assignments to credential
names. Typed patterns run before the generic entropy rule so one byte range does
not become duplicate candidates. Placeholder vocabulary and low-entropy values
are negative controls, not findings.

## Privacy and persisted state

The detector never puts a candidate value in its model inventory, local report,
baseline, error, or diagnostic output. Each candidate contains only:

- a rule, category, severity, repository-relative path, line, and column;
- length, character classes, entropy band, and a `[redacted:N]` shape; and
- an HMAC-SHA-256 fingerprint made with a random local 256-bit key.

The key is created with exclusive-create semantics beneath
`COPILOT_SECURITY_HOME/copilot-security-home/secret-scanner/fingerprint.key`.
The scanner rejects links, a wrong key length, non-regular files, and state
directories that resolve outside the private runtime home. On Windows the
parent runtime home receives the scanner's private ACL; Unix key and directory
modes are `0600` and `0700`.

Redacted JSONL audit reports are written to
`copilot-security-home/secret-scanner/reports/<scan-id>.jsonl`. A report starts
with bounded scan/candidate/suppression counts and then records both active and
suppressed candidates. Baseline justifications remain only in the local
baseline file and are not copied into reports. The model receives only the
summary and active rows, without the local baseline path. It is instructed not
to view the candidate line merely to recover or validate the value.

The summary records the exact file, per-file byte, total-byte, and candidate
limits plus `truncated`. Reaching any bound is visible in both the local report
and model inventory and forbids a repository-wide no-secrets conclusion; it is
never silently presented as a complete negative result.

This privacy boundary describes the deterministic candidate channel. Copilot
still reviews the selected repository as part of the broader security scan and
can independently encounter source text. Repository owners should revoke real
credentials before scanning whenever possible.

## Expiring justified baselines

Each repository gets an empty default baseline whose file name is a keyed HMAC
of its canonical local root. A different baseline can be selected through the
SDK `secretBaselinePath`, CLI `--secret-baseline`, or either desktop GUI. The
file uses this strict schema:

```json
{
  "schemaVersion": "1.0",
  "entries": [
    {
      "fingerprint": "hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "ruleId": "generic-high-entropy-secret",
      "path": "test/fixtures/config.env",
      "justification": "Synthetic credential accepted only in the isolated fixture.",
      "expiresAt": "2026-09-01T00:00:00.000Z"
    }
  ]
}
```

All five entry fields are mandatory. `path` must be an exact contained relative
path, justification must be substantive, and `expiresAt` must be a canonical
UTC timestamp. Suppression requires an exact fingerprint, rule, and normalized
path match and applies only while the deadline is in the future. Expired
entries automatically return to the active inventory and increment the audit
report's expired-baseline count. Malformed, duplicate, linked, oversized, or
missing explicitly selected baselines fail before Copilot is invoked.

Fingerprints deliberately bind the local HMAC key, canonical repository root,
rule, path, and candidate value. Moving a line does not invalidate a baseline,
but moving the file, changing the value, changing the rule, moving the
repository, or using another `COPILOT_SECURITY_HOME` does. Baselines therefore
cannot act as portable hashes of known credentials and cannot silently suppress
the same bytes in another checkout.

```powershell
node ./bin/copilot-security.mjs scan C:\code\project `
  --secret-baseline C:\security-policy\project-secrets.json
```

Do not commit a real candidate, its plaintext, or the local fingerprint key to
create a baseline. Copy only the opaque fingerprint and redacted metadata from
the local JSONL report, add a narrow justification and short expiry, then
review renewals as security exceptions. A justification containing the exact
candidate bytes fails closed instead of suppressing or copying them.

## Deterministic benchmark

`benchmarks/secret-candidate-manifest.json` is a model-free corpus of typed
positives and negative controls. It stores construction fragments rather than
assembled credential-shaped strings, materializes each case only in a private
temporary repository, requires perfect precision and recall, and asserts that
none of the generated values appears in the returned inventory. The regression
suite separately covers fingerprint stability and scope, baseline expiry,
binary/generated/link rejection, state-link escape, malformed key and baseline
failure, and prompt-tag injection.
