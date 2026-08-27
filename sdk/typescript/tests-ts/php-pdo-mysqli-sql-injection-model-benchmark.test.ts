import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  phpSqlInjectionRecords,
  type PhpSqlInjectionRecord,
} from "../src/php-sql-risk.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    expected: Array<{
      cwe?: string[];
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
      requiredValidationTextAnyOf?: string[][];
      requiredAttackPathTextAnyOf?: string[][];
      forbiddenText?: string[];
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "php-pdo-tainted-prepared-sql-injection",
  "php-pdo-parameterized-query",
] as const;

function records(source: string, path = "search.php"): PhpSqlInjectionRecord[] {
  return phpSqlInjectionRecords(path, source.split(/\r?\n/u), source);
}

async function fixtureRecords(
  id: (typeof caseIds)[number],
): Promise<PhpSqlInjectionRecord[]> {
  const inventory = await buildResidualRiskInventory(
    join(benchmarkRoot, "fixtures", id),
  );
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as PhpSqlInjectionRecord)
    .filter(
      (record) => record.frameworkModel?.id === "php-pdo-mysqli-sql-injection",
    );
}

describe("PHP PDO and MySQLi SQL-injection model benchmark", () => {
  test("keeps tainted query grammar and parameter data under perfect gates", async () => {
    const benchmark = JSON.parse(
      await readFile(
        join(benchmarkRoot, "php-pdo-sql-injection-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(benchmark.schemaVersion).toBe("1.0");
    expect(
      Object.values(benchmark.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(benchmark.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(benchmark.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-89"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(4);
    expect(
      benchmark.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(4);
    expect(benchmark.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(benchmark.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact HTTP source, interpolation, preparation, and execution", async () => {
    const vulnerable = await fixtureRecords(caseIds[0]);
    const safe = await fixtureRecords(caseIds[1]);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "src/search.php",
      line: 10,
      categories: ["php-pdo-mysqli-sql-injection"],
      frameworkModel: {
        schemaVersion: "1.2",
        id: "php-pdo-mysqli-sql-injection",
        language: "php",
        scope: "same-file",
        source: {
          kind: "php-http-input",
          path: "src/search.php",
          line: 7,
          symbol: "$_GET[email]",
        },
        sink: {
          kind: "pdo-tainted-prepared-execution",
          path: "src/search.php",
          line: 10,
          symbol:
            "database=pdo;receiver=$database;statement=$statement;prepareLine=9;method=execute",
          cweIds: ["CWE-89"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual([
      "php-variable-assignment",
      "php-string-interpolation",
      "php-variable-assignment",
      "php-database-prepare",
    ]);
    expect(safe).toEqual([]);
  });

  test("keeps the pair topology identical apart from grammar and parameter binding", async () => {
    const vulnerable = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[0], "src", "search.php"),
      "utf8",
    );
    const safe = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[1], "src", "search.php"),
      "utf8",
    );
    const repaired = vulnerable
      .replace("WHERE email = '$email'", "WHERE email = ?")
      .replace("$statement->execute();", "$statement->execute([$email]);");
    expect(repaired).toBe(safe);
  });

  test("keeps executable witnesses and their dedicated hosted gate", async () => {
    const vulnerable = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[0], "witness.php"),
      "utf8",
    );
    const safe = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[1], "witness.php"),
      "utf8",
    );
    const attack = `$_GET["email"] = "' OR 1=1 -- ";`;
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain(attack);
      expect(witness).toContain("sqlite::memory:");
      expect(witness).toContain("admin@example.test");
      expect(witness).toContain("user@example.test");
    }
    expect(vulnerable).toContain("count($rows) !== 2");
    expect(vulnerable).toContain('echo "injected_rows=2\\n"');
    expect(safe).toContain("count($rows) !== 0");
    expect(safe).toContain('echo "parameterized_rows=0\\n"');

    const workflow = await readFile(
      resolve(
        benchmarkRoot,
        "..",
        ".github",
        "workflows",
        "php-fixture-ci.yml",
      ),
      "utf8",
    );
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(workflow).toContain(
      "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    );
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain("php-sqlite3");
    expect(workflow).toContain(
      "php-pdo-tainted-prepared-sql-injection/witness.php",
    );
    expect(workflow).toContain("php-pdo-parameterized-query/witness.php");
    expect(workflow).toContain('test "$vulnerable" = "injected_rows=2"');
    expect(workflow).toContain('test "$control" = "parameterized_rows=0"');
  });

  test("recognizes direct PDO and object or procedural MySQLi execution", () => {
    const pdo = records(`<?php
$database = new \\PDO("sqlite::memory:");
$name = $_POST["name"];
$database->query("SELECT * FROM users WHERE name = '" . $name . "'");
`);
    expect(pdo).toHaveLength(1);
    expect(pdo[0]?.frameworkModel.sink.kind).toBe("pdo-direct-sql-execution");
    expect(pdo[0]?.frameworkModel.sink.symbol).toContain("method=query");
    expect(pdo[0]?.frameworkModel.sink.symbol).toContain("receiver=$database");

    const mysqliObject = records(`<?php
function remove(mysqli $database): void {
  $id = filter_input(INPUT_GET, "id");
  $database->multi_query(sprintf("DELETE FROM sessions WHERE id = '%s'", $id));
}
`);
    expect(mysqliObject).toHaveLength(1);
    expect(mysqliObject[0]?.frameworkModel.sink.kind).toBe(
      "mysqli-direct-sql-execution",
    );

    const mysqliProcedural = records(`<?php
$database = mysqli_connect("db", "app", "secret", "app");
$name = $_REQUEST["name"];
$query = "SELECT * FROM users WHERE name = '$name'";
mysqli_query($database, $query);
`);
    expect(mysqliProcedural).toHaveLength(1);
    expect(mysqliProcedural[0]?.frameworkModel.sink.symbol).toContain(
      "method=mysqli_query",
    );

    const mysqliExecuteQuery = records(`<?php
$database = mysqli_connect("db", "app", "secret", "app");
$name = $_GET["name"];
mysqli_execute_query($database, "SELECT * FROM users WHERE name = '$name'");
`);
    expect(mysqliExecuteQuery).toHaveLength(1);
    expect(mysqliExecuteQuery[0]?.frameworkModel.sink.symbol).toContain(
      "method=mysqli_execute_query",
    );
  });

  test("recognizes typed class properties without crossing class identity", () => {
    const promoted = records(`<?php
final class UserRepository {
  public function __construct(private readonly PDO $database) {}
  public function find(): void {
    $email = $_GET["email"];
    $this->database->query("SELECT * FROM users WHERE email = '$email'");
  }
}
`);
    expect(promoted).toHaveLength(1);
    expect(promoted[0]?.frameworkModel.sink.kind).toBe(
      "pdo-direct-sql-execution",
    );

    const property = records(`<?php
final class UserRepository {
  private mysqli $database;
  public function find(): void {
    $email = $_GET["email"];
    $this->database->query("SELECT * FROM users WHERE email = '$email'");
  }
}
`);
    expect(property).toHaveLength(1);
    expect(property[0]?.frameworkModel.sink.kind).toBe(
      "mysqli-direct-sql-execution",
    );

    const isolated = records(`<?php
final class PdoOwner { private PDO $database; }
final class Lookalike {
  public function find(PDO $database): void {
    $email = $_GET["email"];
    $this->database->query("SELECT * FROM users WHERE email = '$email'");
  }
}
`);
    expect(isolated).toEqual([]);
  });

  test("requires execution after a tainted PDO or MySQLi preparation", () => {
    const pdo = records(`<?php
function lookup(PDO $database): void {
  $query = "SELECT * FROM users WHERE id = " . $_GET["id"];
  $database->prepare($query)->execute();
}
`);
    expect(pdo).toHaveLength(1);
    expect(pdo[0]?.frameworkModel.sink.kind).toBe(
      "pdo-tainted-prepared-execution",
    );

    const mysqli = records(`<?php
$database = mysqli_connect("db", "app", "secret", "app");
$query = "SELECT * FROM users WHERE id = " . $_GET["id"];
$statement = mysqli_prepare($database, $query);
mysqli_stmt_execute($statement);
`);
    expect(mysqli).toHaveLength(1);
    expect(mysqli[0]?.frameworkModel.sink.kind).toBe(
      "mysqli-tainted-prepared-execution",
    );

    expect(
      records(`<?php
$database = new PDO("sqlite::memory:");
$query = "SELECT * FROM users WHERE id = " . $_GET["id"];
$statement = $database->prepare($query);
`),
    ).toEqual([]);
  });

  test("tracks interpolation, concatenation, formatting, filter_input, and heredoc", () => {
    const heredoc = records(`<?php
function lookup(PDO $database): void {
  $email = filter_input(INPUT_POST, "email");
  $query = <<<SQL
SELECT * FROM users WHERE email = '$email'
SQL;
  $database->exec($query);
}
`);
    expect(heredoc).toHaveLength(1);
    expect(heredoc[0]?.frameworkModel.source.symbol).toBe(
      "filter_input(INPUT_POST,email)",
    );
    expect(
      heredoc[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("php-string-interpolation");

    const formatted = records(`<?php
$database = new mysqli("db", "app", "secret", "app");
$email = $_COOKIE["email"];
$query = sprintf("SELECT * FROM users WHERE email = '%s'", $email);
$database->real_query($query);
`);
    expect(formatted).toHaveLength(1);
    expect(
      formatted[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("php-string-formatting");

    const appendedSource = `<?php
#[SensitiveParameter]
function lookup(PDO $database): void {
  $query = "SELECT * FROM users WHERE user_agent = '";
  $query .= $_SERVER["HTTP_USER_AGENT"];
  $query .= "'";
  $database->query($query);
}
`;
    const appended = records(appendedSource, "template.phtml");
    expect(appended).toHaveLength(1);
    expect(appended[0]?.frameworkModel.source.symbol).toBe(
      "$_SERVER[HTTP_USER_AGENT]",
    );
    expect(
      appended[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("php-string-concatenation");
  });

  test("rejects parameter data, fixed queries, scalar conversion, and fixed selection", () => {
    const controls = [
      `<?php
function lookup(PDO $database): void {
  $email = $_GET["email"];
  $statement = $database->prepare("SELECT * FROM users WHERE email = ?");
  $statement->execute([$email]);
}
`,
      `<?php
$database = new PDO("sqlite::memory:");
$database->query("SELECT id FROM users ORDER BY id");
`,
      `<?php
$database = new PDO("sqlite::memory:");
$id = (int) $_GET["id"];
$database->query("SELECT * FROM users WHERE id = " . $id);
`,
      `<?php
$database = new PDO("sqlite::memory:");
$direction = ($_GET["direction"] ?? "") === "desc" ? "DESC" : "ASC";
$database->query("SELECT * FROM users ORDER BY created_at " . $direction);
`,
      `<?php
$database = new PDO("sqlite::memory:");
$id = filter_input(INPUT_GET, "id", FILTER_VALIDATE_INT);
$database->query("SELECT * FROM users WHERE id = " . $id);
`,
      `<?php
$database = new PDO("sqlite::memory:");
$address = $_SERVER["REMOTE_ADDR"];
$database->query("SELECT * FROM sessions WHERE address = '$address'");
`,
      `<?php
$database = mysqli_connect("db", "app", "secret", "app");
mysqli_execute_query($database, "SELECT * FROM users WHERE email = ?", [$_GET["email"]]);
`,
      `<?php
$database = new PDO("sqlite::memory:");
$database->query($_GET);
`,
    ];
    for (const control of controls) expect(records(control)).toEqual([]);
  });

  test("rejects reassignment, scope confusion, inert SQL, lookalikes, and non-code text", () => {
    const controls = [
      `<?php
$database = new PDO("sqlite::memory:");
$email = $_GET["email"];
$email = "service@example.test";
$database->query("SELECT * FROM users WHERE email = '$email'");
`,
      `<?php
function source(): void { $query = $_GET["query"]; }
function sink(PDO $database): void { $database->exec($query); }
`,
      `<?php
$database = new PDO("sqlite::memory:");
$query = "SELECT * FROM users WHERE id = " . $_GET["id"];
error_log($query);
`,
      `<?php
$database = new LocalDatabase();
$database->query("SELECT * FROM users WHERE id = " . $_GET["id"]);
`,
      `<p>$database->query($_GET["id"])</p>
<?php // $database = new PDO(); $database->query($_GET["id"]); ?>
`,
      `<?php
$example = '$database->query($_GET["id"])';
`,
    ];
    for (const control of controls) expect(records(control)).toEqual([]);
    expect(records(controls[0]!, "search.php.txt")).toEqual([]);
  });

  test("retains manual escaping as a control for model validation", () => {
    const found = records(`<?php
function lookup(mysqli $database): void {
  $email = $_GET["email"];
  $escaped = $database->real_escape_string($email);
  $database->query("SELECT * FROM users WHERE email = '$escaped'");
}
`);
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.candidateControls).toEqual([
      {
        kind: "database-string-escaping-requires-same-connection-and-context",
        path: "search.php",
        line: 4,
      },
    ]);
  });

  test("fails closed on malformed, excessive, and deeply nested PHP", () => {
    expect(records("<?php /* unterminated")).toEqual([]);
    expect(
      records(
        "<?php function broken(PDO $database) { $database->query($_GET['x']);",
      ),
    ).toEqual([]);
    expect(
      records(`<?php ${"(".repeat(130)}$_GET["id"]${")".repeat(130)};`),
    ).toEqual([]);
    expect(records(`<?php ${"$x;".repeat(131_073)}`)).toEqual([]);
  });

  test("bounds record and excerpt amplification and skips abstract declarations", () => {
    const calls = Array.from(
      { length: 70 },
      (_, index) =>
        `$database->query("SELECT * FROM users WHERE id = " . $_GET["id${index}"]);`,
    ).join("\n");
    const capped = records(`<?php
$database = new PDO("sqlite::memory:");
${calls}
`);
    expect(capped).toHaveLength(64);
    expect(new Set(capped.map(({ line }) => line)).size).toBe(64);

    const long = records(`<?php
$database = new PDO("sqlite::memory:");
$database->query("${"a".repeat(5_000)}" . $_GET["id"]);
`);
    expect(long).toHaveLength(1);
    expect(long[0]?.excerpt).toContain("…[truncated]");
    expect(long[0]?.excerpt.length).toBeLessThan(2_200);

    const afterAbstractMethod = records(`<?php
interface Searcher { public function search(string $query): array; }
function search(PDO $database): void {
  $database->query("SELECT * FROM users WHERE email = '" . $_GET["email"] . "'");
}
`);
    expect(afterAbstractMethod).toHaveLength(1);
    expect(afterAbstractMethod[0]?.frameworkModel.sink.line).toBe(4);
  });

  test("gives the correction turn PHP-specific validation boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"php-pdo-mysqli-sql-injection"}}',
    );
    expect(prompt).toContain("For php-pdo-mysqli-sql-injection rows");
    expect(prompt).toContain("PDO or MySQLi");
    expect(prompt).toContain("prepare");
    expect(prompt).toContain("parameter data");
    expect(prompt).toContain("does not prove database reachability");
    expect(prompt).toContain("CWE-89");
  });
});
