import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const probe = [
  "import argparse, json, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import deep_scan_workbench as deep",
  "class Connection:",
  "    def __init__(self): self.calls = []; self.rolled_back = False",
  "    def execute(self, sql, params=()): self.calls.append(sql); return self",
  "    def rollback(self): self.rolled_back = True",
  "def check(command, gate):",
  "    connection = Connection()",
  "    deep.require_deep_scan_run = lambda connection, scan_id: {'status': 'running'}",
  "    if gate == 'owner':",
  "        deep.require_owned_scan = lambda connection, scan_id, thread_id: (_ for _ in ()).throw(SystemExit('wrong owner'))",
  "    else:",
  "        deep.require_owned_scan = lambda connection, scan_id, thread_id: ({'handoff_status': 'pending', 'handoff_claim_token': 'expected'}, {})",
  "        deep.require_current_continuation = lambda scan, token, error_message: (_ for _ in ()).throw(SystemExit('wrong continuation'))",
  "    common = {'scan_id': '12345678-1234-4234-8234-123456789abc', 'thread_id': 'thread-attacker', 'claim_token': '12345678-1234-4234-8234-123456789abc'}",
  "    args = argparse.Namespace(**common, **({'message': 'failed', 'manifest_path': None, 'deep_status': 'failed'} if command == 'fail' else {'terminal_reason': 'capped', 'manifest_path': 'unused', 'omitted_worker_id': []}))",
  "    try:",
  "        (deep.fail_deep_scan if command == 'fail' else deep.finish_deep_scan)(connection, args)",
  "    except SystemExit as error:",
  "        return {'command': command, 'gate': gate, 'error': str(error), 'rolledBack': connection.rolled_back, 'statements': len(connection.calls)}",
  "    raise AssertionError('terminal mutation unexpectedly succeeded')",
  "print(json.dumps([check(command, gate) for command in ('fail', 'finish') for gate in ('owner', 'continuation')]))",
].join("\n");

describe("Deep Scan terminal ownership", () => {
  test("checks the owner and current continuation before terminal mutation", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null) return;
    const result = Bun.spawnSync(
      [python, "-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(new TextDecoder().decode(result.stderr)).toBe("");
    expect(result.exitCode).toBe(0);
    const checks = JSON.parse(
      new TextDecoder().decode(result.stdout),
    ) as Array<{
      error: string;
      rolledBack: boolean;
      statements: number;
    }>;
    expect(checks).toHaveLength(4);
    expect(checks.map((check) => check.error)).toEqual([
      "wrong owner",
      "wrong continuation",
      "wrong owner",
      "wrong continuation",
    ]);
    expect(checks.every((check) => check.rolledBack)).toBeTrue();
    expect(checks.every((check) => check.statements === 1)).toBeTrue();
  });
});
