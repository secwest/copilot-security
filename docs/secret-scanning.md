# Local secret candidate scanning

Copilot Security runs a deterministic secret-candidate pass in the trusted host
before starting a Copilot model session. The pass covers every bounded plaintext
file for repository scans and the immutable host inventory for scoped and diff
scans. It ignores links, binary data, generated dependency/build trees,
oversized files, and paths that escape the registered repository.

The same pass examines unique plaintext Git blobs reachable from the newest
128 commits by default. This catches a credential deleted from the working tree
but retained on a branch or other reachable ref. `--secret-history-depth 0`
disables only history; the current-tree pass remains mandatory. The supported
range is 0 through 2048 commits.

The detector currently recognizes high-confidence GitHub, GitLab, Slack,
Stripe, npm, PyPI, SendGrid, Google, and AWS credential forms, private-key
markers, and quoted or dotenv-style high-entropy assignments to credential
names. Typed patterns run before the generic entropy rule so one byte range does
not become duplicate candidates. Placeholder vocabulary and low-entropy values
are negative controls, not findings. Multi-segment uppercase identifiers ending
in a credential environment suffix, such as `SERVICE_ACCESS_TOKEN`, are also
treated as references rather than values; this is intentionally narrower than
ignoring tests, fixtures, or all uppercase strings.

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

The summary records the exact current-file, per-file byte, total-byte, candidate,
history-depth, enumeration-byte, object, blob, historical-byte, occurrence,
command-time, and retained-object-ID limits plus `truncated`. Reaching any bound
is visible in both the local report and model inventory and forbids a
repository-wide or history-wide no-secrets conclusion; it is never silently
presented as a complete negative result.

This privacy boundary describes the deterministic candidate channel. Copilot
still reviews the selected repository as part of the broader security scan and
can independently encounter source text. Repository owners should revoke real
credentials before scanning whenever possible.

## Reachable Git history

History scanning uses the same trusted executable resolver as the rest of the
scanner. A `git` candidate inside the target or another protected path is not
eligible. Before each history command the scanner removes ambient `GIT_*`
variables, disables system/global Git configuration, replacement objects, lazy
object fetching, optional locks, and pagers, and uses argument arrays without a
shell. The canonical target root is supplied as the one command-line
`safe.directory`, because disabled global configuration must not make a valid
scanner-owned checkout fail Git's ownership check. No ambient safe-directory
entry is restored. Repository content is never checked out and Git command
diagnostics are not copied into reports or prompts.

The scanner asks Git for objects reachable from the selected bounded commit
horizon, retains only safe contained paths, and batch-checks object type and
size before reading content. It skips ignored generated directories, known
binary extensions, binary bytes, invalid UTF-8-like content, non-blobs, and
blobs over 512 KiB. The remaining blobs are batch-read with a 60-second command
ceiling and these history-specific bounds:

- 8 MiB object-list output;
- 8,000 named objects;
- 4,000 plaintext blobs;
- 64 MiB aggregate blob content;
- 8,000 candidate occurrences; and
- eight retained blob IDs per deduplicated candidate.

The same blob is scanned once even when multiple commits reference it. The same
rule, path, and value across different blobs has one candidate identity and an
aggregate object count. Up to eight immutable blob IDs are retained as bounded
provenance; `objectIdsTruncated` says when more existed. A candidate also in the
working tree keeps `source=working_tree` and receives the historical metadata.
A deleted-only candidate uses `source=git_history`.

History state is explicit: `disabled`, `not_git_repository`, `unavailable`,
`complete`, `partial`, or `error`. A requested history pass with unavailable
trusted Git, malformed or missing objects, a timeout, or a resource cutoff is
partial and makes overall `truncated=true`. A directory with no `.git` marker
is instead `not_git_repository`, because there is no repository history to
claim was examined.

Copilot receives only the redacted row and bounded blob IDs. It is explicitly
forbidden from using `git show`, `cat-file`, patch logs, or another history read
merely to reconstruct the value. Historical presence proves exposure in a
reachable object, not that the credential is still accepted by its issuer;
reports must recommend revocation and history cleanup without claiming current
validity or reproducing the credential.

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
  --secret-baseline C:\security-policy\project-secrets.json `
  --secret-history-depth 512
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

`benchmarks/secret-history-manifest.json` is the matching real-Git corpus. It
commits fragment-materialized typed and generic credentials, preserves one
credential in two distinct blobs, deletes the corpus from the working tree,
and requires the history pass to recover exactly the three positive identities
while rejecting placeholder and public-key controls. It gates precision and
recall at 1.0, proves blob-level deduplication, and asserts that no materialized
value appears in either model inventory or the private redacted report.
