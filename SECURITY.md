# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to `dr@secwest.net`. Include the
affected version or commit, platform, reproduction steps, security impact, and
any suggested mitigation. Do not publish exploit details before coordinated
disclosure.

## Scope

Reports are in scope when they affect this repository's scanner, SDK, CLI,
container, bundled Copilot plugin, deterministic workbench, artifact
validation, benchmark evaluator, or release automation.

High-value classes include:

- command or argument injection across the CLI, Git, Python, or Copilot
  process boundaries;
- repository-controlled code escaping the target or output boundaries;
- credential, token, environment, prompt, log, or artifact disclosure;
- symlink, traversal, race, or archive extraction flaws;
- contract or sealing bypasses that permit forged findings or reports;
- unintended repository modification, publication, network access, or
  third-party side effects;
- state or credential overlap with another scanner or Copilot installation;
- benchmark manipulation that hides false positives, false negatives, or
  incomplete scans;
- denial of service that strands child processes, locks, or partial state.

## Security invariants

- Scanner-owned state is rooted at `COPILOT_SECURITY_HOME` and uses only the
  `copilot-security` namespace.
- Copilot CLI authentication is owned by Copilot CLI. Scanner code does not
  copy or persist GitHub tokens.
- Scan output must be outside the target repository and enclosing worktree.
- Repository content is untrusted data and cannot change scanner policy.
- The model writes draft artifacts only; deterministic code validates,
  projects, and seals canonical results.
- Report-only scans do not modify repositories, publish findings, open issues,
  commit, push, or contact third parties.
- Missing or malformed artifacts are scan failures and benchmark completion
  failures, never successful empty scans.

## Supported versions

Until the first stable release, security fixes target the current `main`
branch. Older development commits may not receive backports.
