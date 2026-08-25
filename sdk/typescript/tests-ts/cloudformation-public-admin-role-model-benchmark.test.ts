import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface CloudFormationRecord {
  path: string;
  line: number;
  categories: string[];
  frameworkModel?: {
    schemaVersion: string;
    id: string;
    language: string;
    scope: string;
    source: { kind: string; path: string; line: number; symbol: string };
    sink: {
      kind: string;
      path: string;
      line: number;
      symbol: string;
      cweIds: string[];
    };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

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
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "cloudformation-public-admin-role",
  "cloudformation-specific-admin-role",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): CloudFormationRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as CloudFormationRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "cloudformation-public-admin-role",
    );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<CloudFormationRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-cloudformation-admin-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function template(
  options: {
    version?: string;
    logicalId?: string;
    type?: string;
    principal?: string;
    action?: string;
    trustExtra?: string;
    managedPolicyArn?: string;
    propertiesExtra?: string;
  } = {},
): string {
  return `AWSTemplateFormatVersion: ${options.version ?? '"2010-09-09"'}
Resources:
  ${options.logicalId ?? "PublicAdmin"}:
    Type: ${options.type ?? "AWS::IAM::Role"}
    Properties:
      RoleName: public-admin
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: ${options.principal ?? '"*"'}
            Action: ${options.action ?? "sts:AssumeRole"}
${options.trustExtra === undefined ? "" : `            ${options.trustExtra}\n`}      ManagedPolicyArns:
        - ${options.managedPolicyArn ?? "arn:aws:iam::aws:policy/AdministratorAccess"}
${options.propertiesExtra === undefined ? "" : `      ${options.propertiesExtra}\n`}`;
}

describe("CloudFormation public administrator role model benchmark", () => {
  test("keeps the public administrator role and specific-principal control under perfect gates", async () => {
    const benchmark = JSON.parse(
      await readFile(
        join(benchmarkRoot, "cloudformation-public-admin-role-manifest.json"),
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
      cwe: ["CWE-269", "CWE-284"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(benchmark.cases[1]?.expected).toEqual([]);
  });

  test("preserves exact role, trust, administrator policy, and line provenance", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "src/template.yaml",
      line: 17,
      categories: ["cloudformation-public-admin-role"],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "cloudformation-yaml-json",
        scope: "same-file",
        source: {
          kind: "unrestricted-wildcard-role-trust",
          path: "src/template.yaml",
          line: 13,
          symbol:
            "principal=AWS:*;effect=Allow;action=sts:AssumeRole;condition=absent",
        },
        sink: {
          kind: "unbounded-administrator-role-permissions",
          path: "src/template.yaml",
          line: 17,
          symbol:
            "managedPolicyArn=arn:aws:iam::aws:policy/AdministratorAccess;permissionsBoundary=absent",
          cweIds: ["CWE-269", "CWE-284"],
        },
        propagators: [
          {
            kind: "cloudformation-iam-role",
            path: "src/template.yaml",
            line: 5,
            symbol:
              "logicalId=PublicAdministratorRole;type=AWS::IAM::Role;roleName=public-administrator",
          },
          {
            kind: "unrestricted-sts-assume-role-statement",
            path: "src/template.yaml",
            line: 14,
            symbol:
              "logicalId=PublicAdministratorRole;principal=AWS:*;effect=Allow;action=sts:AssumeRole;condition=absent",
          },
        ],
        candidateControls: [],
      },
    });
    expect(safe).toEqual([]);
  });

  test("supports YAML, JSON, template files, intrinsic tags, and AWS partitions", async () => {
    const cases: Array<[string, string]> = [
      ["template.yaml", "arn:aws:iam::aws:policy/AdministratorAccess"],
      ["template.yml", "arn:aws-cn:iam::aws:policy/AdministratorAccess"],
      ["stack.template", "arn:aws-us-gov:iam::aws:policy/AdministratorAccess"],
    ];
    for (const [path, arn] of cases) {
      const source = `${template({ managedPolicyArn: arn })}Outputs:\n  RoleArn:\n    Value: !GetAtt PublicAdmin.Arn\n  Label:\n    Value: !Sub [hello, {name: world}]\n`;
      expect(await repositoryInventory({ [path]: source })).toHaveLength(1);
    }
    const json = JSON.stringify({
      AWSTemplateFormatVersion: "2010-09-09",
      Resources: {
        PublicAdmin: {
          Type: "AWS::IAM::Role",
          Properties: {
            AssumeRolePolicyDocument: {
              Version: "2012-10-17",
              Statement: {
                Effect: "Allow",
                Principal: "*",
                Action: ["sts:GetCallerIdentity", "STS:ASSUMEROLE"],
              },
            },
            ManagedPolicyArns: ["arn:aws:iam::aws:policy/AdministratorAccess"],
          },
        },
      },
    });
    expect(await repositoryInventory({ "stack.json": json })).toHaveLength(1);
  });

  test("recognizes exact unbounded inline administrator permissions", async () => {
    const inline = template({
      managedPolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess",
      propertiesExtra: `Policies:
        - PolicyName: root
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - "*"
                Resource: "*"`,
    });
    const rows = await repositoryInventory({ "inline.yaml": inline });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.symbol).toContain(
      "inlinePolicy=root;effect=Allow;action=*;resource=*",
    );
  });

  test("treats trust conditions, permissions boundaries, and narrower authority as exact controls", async () => {
    const controls = [
      template({
        trustExtra:
          'Condition:\n              StringEquals:\n                "sts:ExternalId": expected',
      }),
      template({
        propertiesExtra:
          "PermissionsBoundary: arn:aws:iam::111122223333:policy/Boundary",
      }),
      template({ principal: "arn:aws:iam::111122223333:root" }),
      template({ action: "sts:GetCallerIdentity" }),
      template({ managedPolicyArn: "arn:aws:iam::aws:policy/PowerUserAccess" }),
      template({ principal: "!Ref TrustedPrincipal" }),
    ];
    for (const [index, source] of controls.entries()) {
      expect(
        await repositoryInventory({ [`control-${index}.yaml`]: source }),
      ).toEqual([]);
    }
  });

  test("does not mistake empty conditions or an AdministratorAccess boundary for restriction", async () => {
    const emptyConditionRows = await repositoryInventory({
      "empty-condition.yaml": template({ trustExtra: "Condition: {}" }),
    });
    expect(emptyConditionRows).toHaveLength(1);
    expect(emptyConditionRows[0]?.frameworkModel?.source.symbol).toContain(
      "condition=empty",
    );
    const rows = await repositoryInventory({
      "unbounded-boundary.yaml": template({
        propertiesExtra:
          "PermissionsBoundary: arn:aws:iam::aws:policy/AdministratorAccess",
      }),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.symbol).toContain(
      "permissionsBoundary=arn:aws:iam::aws:policy/AdministratorAccess",
    );
  });

  test("fails closed on invalid shapes, ambiguity, aliases, and non-templates", async () => {
    const base = template();
    const controls: Record<string, string> = {
      "wrong-version.yaml": template({ version: '"2000-01-01"' }),
      "wrong-type.yaml": template({ type: "AWS::IAM::ManagedPolicy" }),
      "duplicate-key.yaml": base.replace(
        "      RoleName: public-admin\n",
        "      RoleName: public-admin\n      RoleName: other\n",
      ),
      "alias.yaml": `${base}Metadata: &metadata\n  name: value\nCopy: *metadata\n`,
      "malformed.yaml": `${base}Broken: [\n`,
      "lookalike.yaml":
        'role:\n  Type: AWS::IAM::Role\n  Principal: "*"\n  ManagedPolicyArns:\n    - arn:aws:iam::aws:policy/AdministratorAccess\n',
      "template.txt": base,
    };
    expect(await repositoryInventory(controls)).toEqual([]);
  });

  test("gives correction exact deployment, caller, and effective-permission boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"cloudformation-public-admin-role"}}',
    );
    expect(prompt).toContain("For cloudformation-public-admin-role rows");
    expect(prompt).toContain("same-account identities may need no separate");
    expect(prompt).toContain("cross-account callers normally need");
    expect(prompt).toContain("PermissionsBoundary");
    expect(prompt).toContain(
      "macros, StackSets, nested stacks, CDK/SAM synthesis",
    );
    expect(prompt).toContain("Do not infer anonymous internet access");
  });
});
