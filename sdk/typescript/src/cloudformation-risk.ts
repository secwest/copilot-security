import {
  isAlias,
  isMap,
  isNode,
  isScalar,
  isSeq,
  LineCounter,
  parseAllDocuments,
  YAMLSeq,
  type CollectionTag,
  type Pair,
  type ScalarTag,
} from "yaml";

const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const CLOUDFORMATION_VERSION = "2010-09-09";
const IAM_POLICY_VERSION = "2012-10-17";
const ADMINISTRATOR_ACCESS_ARNS = new Set([
  "arn:aws:iam::aws:policy/AdministratorAccess",
  "arn:aws-cn:iam::aws:policy/AdministratorAccess",
  "arn:aws-us-gov:iam::aws:policy/AdministratorAccess",
]);
const CLOUDFORMATION_INTRINSIC_TAGS = [
  "And",
  "Base64",
  "Cidr",
  "Condition",
  "Equals",
  "FindInMap",
  "ForEach",
  "GetAtt",
  "GetAZs",
  "If",
  "ImportValue",
  "Join",
  "Length",
  "Not",
  "Or",
  "Ref",
  "Select",
  "Split",
  "Sub",
  "ToJsonString",
  "Transform",
] as const;

const cloudFormationTags: Array<ScalarTag | CollectionTag> =
  CLOUDFORMATION_INTRINSIC_TAGS.flatMap((name) => [
    {
      tag: `!${name}`,
      resolve: (value: string) => ({ intrinsic: name, value }),
    } satisfies ScalarTag,
    {
      tag: `!${name}`,
      collection: "seq",
      nodeClass: YAMLSeq,
    } satisfies CollectionTag,
  ]);

interface CandidateControl {
  kind: string;
  path: string;
  line: number;
}

export interface CloudFormationPublicAdminRoleRecord {
  path: string;
  line: number;
  categories: ["cloudformation-public-admin-role"];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "cloudformation-public-admin-role";
    language: "cloudformation-yaml-json";
    scope: "same-file";
    source: {
      kind: "unrestricted-wildcard-role-trust";
      path: string;
      line: number;
      symbol: string;
    };
    sink: {
      kind: "unbounded-administrator-role-permissions";
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-269", "CWE-284"];
    };
    propagators: Array<{
      kind:
        | "cloudformation-iam-role"
        | "unrestricted-sts-assume-role-statement";
      path: string;
      line: number;
      symbol: string;
    }>;
    candidateControls: CandidateControl[];
  };
}

interface ParsedDocuments {
  roots: unknown[];
  counter: LineCounter;
}

interface PublicTrust {
  principalLine: number;
  actionLine: number;
  symbol: string;
}

interface AdministratorGrant {
  line: number;
  symbol: string;
}

function mapPair(node: unknown, key: string): Pair | undefined {
  if (!isMap(node)) return undefined;
  return node.items.find(
    (pair) => isScalar(pair.key) && pair.key.value === key,
  );
}

function scalarText(node: unknown): string | undefined {
  if (!isScalar(node)) return undefined;
  return typeof node.value === "string" ? node.value : undefined;
}

function containsAlias(node: unknown): boolean {
  if (isAlias(node)) return true;
  if (isMap(node)) {
    return node.items.some(
      (pair) => containsAlias(pair.key) || containsAlias(pair.value),
    );
  }
  return isSeq(node) && node.items.some((item) => containsAlias(item));
}

function parseDocuments(source: string): ParsedDocuments | undefined {
  const counter = new LineCounter();
  const documents = parseAllDocuments(source, {
    customTags: cloudFormationTags,
    lineCounter: counter,
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
    version: "1.2",
  });
  if (
    documents.some(
      (document) =>
        document.errors.length > 0 || containsAlias(document.contents),
    )
  ) {
    return undefined;
  }
  return {
    roots: documents
      .map((document) => document.contents)
      .filter((contents) => contents !== null),
    counter,
  };
}

function nodeLine(node: unknown, counter: LineCounter): number | undefined {
  if (!isNode(node) || node.range === null || node.range === undefined) {
    return undefined;
  }
  return counter.linePos(node.range[0]).line;
}

function pairLine(pair: Pair | undefined, counter: LineCounter): number {
  return nodeLine(pair?.key, counter) ?? nodeLine(pair?.value, counter) ?? 1;
}

function sourceExcerpt(
  lines: readonly string[],
  startLine: number,
  endLine: number,
): string {
  return lines
    .slice(startLine - 1, endLine)
    .map((line, offset) => `${startLine + offset}: ${line}`)
    .join("\n");
}

function contextExcerpt(
  lines: readonly string[],
  line: number,
): { startLine: number; endLine: number; excerpt: string } {
  const startLine = Math.max(1, line - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(lines.length, line + CONTEXT_LINES_AFTER);
  return {
    startLine,
    endLine,
    excerpt: sourceExcerpt(lines, startLine, endLine),
  };
}

function scalarList(node: unknown): string[] | undefined {
  const scalar = scalarText(node);
  if (scalar !== undefined) return [scalar];
  if (!isSeq(node)) return undefined;
  const values = node.items.map(scalarText);
  return values.every((value): value is string => value !== undefined)
    ? values
    : undefined;
}

function statementList(node: unknown): unknown[] | undefined {
  if (isMap(node)) return [node];
  if (!isSeq(node) || node.items.some((item) => !isMap(item))) {
    return undefined;
  }
  return node.items;
}

function validPolicyVersion(document: unknown): boolean {
  const versionPair = mapPair(document, "Version");
  return (
    versionPair === undefined ||
    scalarText(versionPair.value) === IAM_POLICY_VERSION
  );
}

function includesCaseInsensitive(
  values: readonly string[],
  accepted: readonly string[],
): boolean {
  const normalized = new Set(values.map((value) => value.toLowerCase()));
  return accepted.some((value) => normalized.has(value.toLowerCase()));
}

function hasRestrictiveCondition(statement: unknown): boolean {
  const conditionPair = mapPair(statement, "Condition");
  if (conditionPair === undefined) return false;
  return !isMap(conditionPair.value) || conditionPair.value.items.length > 0;
}

function wildcardPrincipalLine(
  principalPair: Pair | undefined,
  counter: LineCounter,
): number | undefined {
  if (principalPair === undefined) return undefined;
  if (scalarText(principalPair.value) === "*") {
    return pairLine(principalPair, counter);
  }
  const awsPair = mapPair(principalPair.value, "AWS");
  const awsPrincipals = scalarList(awsPair?.value);
  return awsPrincipals?.includes("*") === true
    ? pairLine(awsPair, counter)
    : undefined;
}

function publicTrusts(
  policy: unknown,
  counter: LineCounter,
): PublicTrust[] | undefined {
  if (!isMap(policy) || !validPolicyVersion(policy)) return undefined;
  const statements = statementList(mapPair(policy, "Statement")?.value);
  if (statements === undefined) return undefined;
  const trusts: PublicTrust[] = [];
  for (const statement of statements) {
    if (!isMap(statement)) return undefined;
    if (scalarText(mapPair(statement, "Effect")?.value) !== "Allow") continue;
    if (
      hasRestrictiveCondition(statement) ||
      mapPair(statement, "NotAction") !== undefined ||
      mapPair(statement, "NotPrincipal") !== undefined
    ) {
      continue;
    }
    const actionPair = mapPair(statement, "Action");
    const actions = scalarList(actionPair?.value);
    if (
      actions === undefined ||
      !includesCaseInsensitive(actions, ["sts:AssumeRole", "sts:*", "*"])
    ) {
      continue;
    }
    const principalPair = mapPair(statement, "Principal");
    const principalLine = wildcardPrincipalLine(principalPair, counter);
    if (principalLine === undefined) continue;
    const condition =
      mapPair(statement, "Condition") === undefined ? "absent" : "empty";
    trusts.push({
      principalLine,
      actionLine: pairLine(actionPair, counter),
      symbol: `principal=AWS:*;effect=Allow;action=sts:AssumeRole;condition=${condition}`,
    });
  }
  return trusts;
}

function managedAdministratorGrants(
  properties: unknown,
  counter: LineCounter,
): AdministratorGrant[] | undefined {
  const managedPolicyPair = mapPair(properties, "ManagedPolicyArns");
  if (managedPolicyPair === undefined) return [];
  if (!isSeq(managedPolicyPair.value)) return undefined;
  const grants: AdministratorGrant[] = [];
  for (const item of managedPolicyPair.value.items) {
    const arn = scalarText(item);
    if (arn === undefined) return undefined;
    if (ADMINISTRATOR_ACCESS_ARNS.has(arn)) {
      grants.push({
        line: nodeLine(item, counter) ?? pairLine(managedPolicyPair, counter),
        symbol: `managedPolicyArn=${arn};permissionsBoundary=absent`,
      });
    }
  }
  return grants;
}

function inlineAdministratorGrants(
  properties: unknown,
  counter: LineCounter,
): AdministratorGrant[] | undefined {
  const policiesPair = mapPair(properties, "Policies");
  if (policiesPair === undefined) return [];
  if (!isSeq(policiesPair.value)) return undefined;
  const policyNames = policiesPair.value.items.map((policy) =>
    scalarText(mapPair(policy, "PolicyName")?.value),
  );
  if (
    policyNames.some(
      (name, index) =>
        name !== undefined && policyNames.indexOf(name) !== index,
    )
  ) {
    return undefined;
  }
  const grants: AdministratorGrant[] = [];
  for (const policy of policiesPair.value.items) {
    if (!isMap(policy)) return undefined;
    const policyName = scalarText(mapPair(policy, "PolicyName")?.value)?.trim();
    const document = mapPair(policy, "PolicyDocument")?.value;
    if (
      policyName === undefined ||
      policyName === "" ||
      !isMap(document) ||
      !validPolicyVersion(document)
    ) {
      continue;
    }
    const statements = statementList(mapPair(document, "Statement")?.value);
    if (statements === undefined) return undefined;
    for (const statement of statements) {
      if (!isMap(statement)) return undefined;
      if (
        scalarText(mapPair(statement, "Effect")?.value) !== "Allow" ||
        hasRestrictiveCondition(statement) ||
        mapPair(statement, "NotAction") !== undefined ||
        mapPair(statement, "NotResource") !== undefined
      ) {
        continue;
      }
      const actionPair = mapPair(statement, "Action");
      const resourcePair = mapPair(statement, "Resource");
      const actions = scalarList(actionPair?.value);
      const resources = scalarList(resourcePair?.value);
      if (
        actions?.includes("*") !== true ||
        resources?.includes("*") !== true
      ) {
        continue;
      }
      grants.push({
        line: pairLine(actionPair, counter),
        symbol: `inlinePolicy=${policyName};effect=Allow;action=*;resource=*;condition=${mapPair(statement, "Condition") === undefined ? "absent" : "empty"};permissionsBoundary=absent`,
      });
    }
  }
  return grants;
}

function administratorGrants(
  properties: unknown,
  counter: LineCounter,
): AdministratorGrant[] | undefined {
  if (!isMap(properties)) return undefined;
  const permissionsBoundaryPair = mapPair(properties, "PermissionsBoundary");
  const permissionsBoundary =
    permissionsBoundaryPair === undefined
      ? "absent"
      : scalarText(permissionsBoundaryPair.value);
  if (
    permissionsBoundary === undefined ||
    (permissionsBoundary !== "absent" &&
      !ADMINISTRATOR_ACCESS_ARNS.has(permissionsBoundary))
  ) {
    return undefined;
  }
  const managed = managedAdministratorGrants(properties, counter);
  const inline = inlineAdministratorGrants(properties, counter);
  if (managed === undefined || inline === undefined) return undefined;
  return [...managed, ...inline]
    .map((grant) => ({
      ...grant,
      symbol: grant.symbol.replace(
        "permissionsBoundary=absent",
        `permissionsBoundary=${permissionsBoundary}`,
      ),
    }))
    .sort((left, right) => left.line - right.line);
}

function roleRecord(
  path: string,
  lines: readonly string[],
  logicalId: string,
  resource: unknown,
  counter: LineCounter,
): CloudFormationPublicAdminRoleRecord | undefined {
  if (!isMap(resource)) return undefined;
  const typePair = mapPair(resource, "Type");
  if (scalarText(typePair?.value) !== "AWS::IAM::Role") return undefined;
  const properties = mapPair(resource, "Properties")?.value;
  if (!isMap(properties)) return undefined;
  const trusts = publicTrusts(
    mapPair(properties, "AssumeRolePolicyDocument")?.value,
    counter,
  );
  const grants = administratorGrants(properties, counter);
  if (
    trusts === undefined ||
    trusts.length === 0 ||
    grants === undefined ||
    grants.length === 0
  ) {
    return undefined;
  }
  const trust = [...trusts].sort(
    (left, right) => left.principalLine - right.principalLine,
  )[0];
  const grant = grants[0];
  if (trust === undefined || grant === undefined) return undefined;
  const roleName = scalarText(mapPair(properties, "RoleName")?.value)?.trim();
  const roleSymbol = `logicalId=${logicalId};type=AWS::IAM::Role;roleName=${roleName || "cloudformation-generated"}`;
  const sinkContext = contextExcerpt(lines, grant.line);
  const sourceContext = contextExcerpt(lines, trust.principalLine);
  return {
    path,
    line: grant.line,
    categories: ["cloudformation-public-admin-role"],
    priority: 100,
    startLine: sinkContext.startLine,
    endLine: sinkContext.endLine,
    excerpt: sinkContext.excerpt,
    sourceExcerpt: sourceContext.excerpt,
    frameworkModel: {
      schemaVersion: "1.2",
      id: "cloudformation-public-admin-role",
      language: "cloudformation-yaml-json",
      scope: "same-file",
      source: {
        kind: "unrestricted-wildcard-role-trust",
        path,
        line: trust.principalLine,
        symbol: trust.symbol,
      },
      sink: {
        kind: "unbounded-administrator-role-permissions",
        path,
        line: grant.line,
        symbol: grant.symbol,
        cweIds: ["CWE-269", "CWE-284"],
      },
      propagators: [
        {
          kind: "cloudformation-iam-role",
          path,
          line: pairLine(typePair, counter),
          symbol: roleSymbol,
        },
        {
          kind: "unrestricted-sts-assume-role-statement",
          path,
          line: trust.actionLine,
          symbol: `logicalId=${logicalId};${trust.symbol}`,
        },
      ],
      candidateControls: [],
    },
  };
}

function templateRecords(
  path: string,
  lines: readonly string[],
  root: unknown,
  counter: LineCounter,
): CloudFormationPublicAdminRoleRecord[] {
  if (!isMap(root)) return [];
  const versionPair = mapPair(root, "AWSTemplateFormatVersion");
  if (
    versionPair !== undefined &&
    scalarText(versionPair.value) !== CLOUDFORMATION_VERSION
  ) {
    return [];
  }
  const resources = mapPair(root, "Resources")?.value;
  if (!isMap(resources)) return [];
  const records: CloudFormationPublicAdminRoleRecord[] = [];
  for (const pair of resources.items) {
    const logicalId = scalarText(pair.key)?.trim();
    if (logicalId === undefined || logicalId === "") continue;
    const record = roleRecord(path, lines, logicalId, pair.value, counter);
    if (record !== undefined) records.push(record);
  }
  return records;
}

export function cloudFormationRiskRecords(
  path: string,
  lines: readonly string[],
  source: string,
): CloudFormationPublicAdminRoleRecord[] {
  if (!/\.(?:json|template|ya?ml)$/iu.test(path)) return [];
  const parsed = parseDocuments(source);
  if (parsed === undefined) return [];
  const records: CloudFormationPublicAdminRoleRecord[] = [];
  for (const root of parsed.roots) {
    records.push(...templateRecords(path, lines, root, parsed.counter));
  }
  return records;
}
