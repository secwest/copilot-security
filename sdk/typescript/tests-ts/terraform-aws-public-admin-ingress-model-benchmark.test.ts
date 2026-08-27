import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";
import {
  terraformRiskRecords,
  type TerraformAwsPublicAdminIngressRecord,
} from "../src/terraform-risk.js";

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
  "terraform-aws-public-admin-ingress",
  "terraform-aws-restricted-admin-ingress",
] as const;

function records(
  source: string,
  path = "main.tf",
): TerraformAwsPublicAdminIngressRecord[] {
  return terraformRiskRecords(path, source.split(/\r?\n/u), source);
}

function inlineRule(
  options: {
    cidr?: string;
    fromPort?: number;
    toPort?: number;
    protocol?: string;
  } = {},
): string {
  return `resource "aws_security_group" "administration" {
  name = "administration"
  ingress {
    from_port   = ${options.fromPort ?? 22}
    to_port     = ${options.toPort ?? 22}
    protocol    = "${options.protocol ?? "tcp"}"
    cidr_blocks = ["${options.cidr ?? "0.0.0.0/0"}"]
  }
}
`;
}

async function fixtureRecords(
  id: (typeof caseIds)[number],
): Promise<TerraformAwsPublicAdminIngressRecord[]> {
  const inventory = await buildResidualRiskInventory(
    join(benchmarkRoot, "fixtures", id),
  );
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as TerraformAwsPublicAdminIngressRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "terraform-aws-public-admin-ingress",
    );
}

describe("Terraform AWS public administration ingress model benchmark", () => {
  test("keeps the public-ingress chain and restricted CIDR control under perfect gates", async () => {
    const benchmark = JSON.parse(
      await readFile(
        join(benchmarkRoot, "terraform-aws-public-admin-ingress-manifest.json"),
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
      cwe: ["CWE-284", "CWE-668"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(3);
    expect(
      benchmark.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(3);
    expect(benchmark.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(benchmark.cases[1]?.expected).toEqual([]);
  });

  test("preserves resource, source, sink, protocol, port, and exact line provenance", async () => {
    const vulnerable = await fixtureRecords(caseIds[0]);
    const safe = await fixtureRecords(caseIds[1]);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "src/security-group.tf",
      line: 10,
      categories: ["terraform-aws-public-admin-ingress"],
      frameworkModel: {
        schemaVersion: "1.2",
        id: "terraform-aws-public-admin-ingress",
        language: "terraform-hcl",
        scope: "same-file",
        source: {
          kind: "unrestricted-ipv4-or-ipv6-ingress",
          path: "src/security-group.tf",
          line: 13,
          symbol: "cidrs=0.0.0.0/0;direction=ingress",
        },
        sink: {
          kind: "remote-administration-port-ingress",
          path: "src/security-group.tf",
          line: 10,
          symbol: "protocol=tcp;fromPort=22;toPort=22;administrationPorts=22",
          cweIds: ["CWE-284", "CWE-668"],
        },
        propagators: [
          {
            kind: "terraform-aws-security-group-resource",
            path: "src/security-group.tf",
            line: 5,
            symbol: "type=aws_security_group;name=administration",
          },
          {
            kind: "literal-ingress-rule",
            path: "src/security-group.tf",
            line: 10,
          },
        ],
        candidateControls: [],
      },
    });
    expect(vulnerable[0]?.frameworkModel.propagators[1]?.symbol).toContain(
      "shape=inline-block",
    );
    expect(safe).toEqual([]);
  });

  test("keeps the benchmark twins identical except for the public CIDR", async () => {
    const vulnerable = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[0], "src", "security-group.tf"),
      "utf8",
    );
    const safe = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[1], "src", "security-group.tf"),
      "utf8",
    );
    expect(vulnerable.replace("0.0.0.0/0", "10.0.0.0/8")).toBe(safe);
  });

  test("supports inline attribute, legacy rule, and current ingress-rule resources", () => {
    const inlineAttribute = records(`resource "aws_security_group" "inline" {
  ingress = [{
    from_port        = 3389
    to_port          = 3389
    protocol         = "udp"
    ipv6_cidr_blocks = ["::/0"]
  }]
}
`);
    expect(inlineAttribute).toHaveLength(1);
    expect(inlineAttribute[0]?.frameworkModel.propagators[1]?.symbol).toContain(
      "shape=inline-attribute",
    );
    expect(inlineAttribute[0]?.frameworkModel.sink.symbol).toContain(
      "administrationPorts=3389",
    );

    const legacy = records(`resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.main.id
  from_port         = 22
  to_port           = 22
  protocol          = 6
  cidr_blocks       = ["0.0.0.0/0"]
}
`);
    expect(legacy).toHaveLength(1);
    expect(legacy[0]?.frameworkModel.propagators[1]?.symbol).toContain(
      "shape=standalone-rule",
    );

    const current =
      records(`resource "aws_vpc_security_group_ingress_rule" "rdp" {
  security_group_id = aws_security_group.main.id
  cidr_ipv6         = "::/0"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
}
`);
    expect(current).toHaveLength(1);
    expect(current[0]?.frameworkModel.propagators[1]?.symbol).toContain(
      "shape=standalone-ingress-rule",
    );
  });

  test("models port ranges and the AWS all-protocol sentinel exactly", () => {
    const ranged = records(inlineRule({ fromPort: 20, toPort: 23 }));
    expect(ranged).toHaveLength(1);
    expect(ranged[0]?.frameworkModel.sink.symbol).toContain(
      "administrationPorts=22",
    );

    const all = records(`resource "aws_vpc_security_group_ingress_rule" "all" {
  security_group_id = aws_security_group.main.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
`);
    expect(all).toHaveLength(1);
    expect(all[0]?.frameworkModel.sink.symbol).toContain(
      "administrationPorts=22,3389",
    );
    expect(all[0]?.frameworkModel.sink.symbol).toContain(
      "fromPort=all;toPort=all",
    );

    const inlineAll = records(
      inlineRule({ fromPort: 0, toPort: 0, protocol: "-1" }),
    );
    expect(inlineAll).toHaveLength(1);
  });

  test("rejects restrictive, non-administrative, egress, computed, and ambiguous rules", () => {
    const controls = [
      inlineRule({ cidr: "10.0.0.0/8" }),
      inlineRule({ fromPort: 443, toPort: 443 }),
      inlineRule({ protocol: "icmp" }),
      inlineRule().replace('protocol    = "tcp"', "protocol    = var.protocol"),
      inlineRule().replace(
        'cidr_blocks = ["0.0.0.0/0"]',
        "cidr_blocks = [var.administration_cidr]",
      ),
      inlineRule().replace(
        'cidr_blocks = ["0.0.0.0/0"]',
        'cidr_blocks = ["${var.prefix}/0"]',
      ),
      inlineRule().replace(
        "    to_port     = 22\n",
        "    to_port     = 22\n    from_port   = 22\n",
      ),
      inlineRule().replace(
        'resource "aws_security_group"',
        'resource "local_security_group"',
      ),
      `resource "aws_security_group_rule" "outbound" {
  type              = "egress"
  security_group_id = aws_security_group.main.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}
`,
      `resource "aws_vpc_security_group_egress_rule" "outbound" {
  security_group_id = aws_security_group.main.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
`,
      `resource "aws_vpc_security_group_ingress_rule" "invalid_all" {
  security_group_id = aws_security_group.main.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "-1"
}
`,
      'resource "aws_security_group" "broken" {\n  ingress {\n',
    ];
    for (const source of controls) expect(records(source)).toEqual([]);
    expect(records(inlineRule(), "main.tf.txt")).toEqual([]);
  });

  test("does not parse commented or heredoc lookalikes and resumes after a heredoc", () => {
    const source = `locals {
  example = <<-EOT
    resource "aws_security_group" "lookalike" {
      ingress { from_port = 22 cidr_blocks = ["0.0.0.0/0"] }
    }
  EOT
}
/* resource "aws_security_group" "comment" { ingress { from_port = 22 } } */
${inlineRule()}`;
    const found = records(source);
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.propagators[0]?.symbol).toBe(
      "type=aws_security_group;name=administration",
    );
    expect(
      records(
        inlineRule().replace(
          'cidr_blocks = ["0.0.0.0/0"]',
          'cidr_blocks = ["0.0.0.0/0",]',
        ),
      ),
    ).toHaveLength(1);
  });

  test("fails closed on adversarial token volume and nesting without throwing", () => {
    const deeplyNested = `${Array.from({ length: 130 }, (_, index) => `outer_${index} {`).join("\n")}\n${Array.from({ length: 130 }, () => "}").join("\n")}\n${inlineRule()}`;
    expect(records(deeplyNested)).toEqual([]);
    expect(records(`${"\n".repeat(131_073)}${inlineRule()}`)).toEqual([]);
  });

  test("gives the correction turn Terraform-specific validation boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"terraform-aws-public-admin-ingress"}}',
    );
    expect(prompt).toContain("For terraform-aws-public-admin-ingress rows");
    expect(prompt).toContain("0.0.0.0/0 or ::/0");
    expect(prompt).toContain("ports 22 or 3389");
    expect(prompt).toContain("rendered Terraform plan");
    expect(prompt).toContain("does not prove that an instance is reachable");
    expect(prompt).toContain("CWE-284 and CWE-668");
  });
});
