const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const MAX_HCL_NESTING = 128;
const MAX_HCL_TOKENS = 131_072;
const ADMINISTRATION_PORTS = [22, 3389] as const;
const PUBLIC_CIDRS = new Set(["0.0.0.0/0", "::/0"]);

type TokenKind = "identifier" | "newline" | "number" | "string" | "symbol";

interface Token {
  kind: TokenKind;
  value: string;
  line: number;
  column: number;
  literal: boolean;
}

interface AttributeItem {
  kind: "attribute";
  name: string;
  line: number;
  expression: Token[];
}

interface BlockItem {
  kind: "block";
  name: string;
  line: number;
  labels: Token[];
  body: BodyItem[];
}

type BodyItem = AttributeItem | BlockItem;

interface CandidateControl {
  kind: string;
  path: string;
  line: number;
}

export interface TerraformAwsPublicAdminIngressRecord {
  path: string;
  line: number;
  categories: ["terraform-aws-public-admin-ingress"];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "terraform-aws-public-admin-ingress";
    language: "terraform-hcl";
    scope: "same-file";
    source: {
      kind: "unrestricted-ipv4-or-ipv6-ingress";
      path: string;
      line: number;
      symbol: string;
    };
    sink: {
      kind: "remote-administration-port-ingress";
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-284", "CWE-668"];
    };
    propagators: Array<{
      kind: "terraform-aws-security-group-resource" | "literal-ingress-rule";
      path: string;
      line: number;
      symbol: string;
    }>;
    candidateControls: CandidateControl[];
  };
}

interface LiteralIngressRule {
  sourceLine: number;
  sinkLine: number;
  cidrs: string[];
  protocol: string;
  fromPort: number | "all";
  toPort: number | "all";
  administrationPorts: number[];
}

function isIdentifierStart(character: string): boolean {
  return /[A-Za-z_]/u.test(character);
}

function isIdentifierPart(character: string): boolean {
  return /[A-Za-z0-9_-]/u.test(character);
}

function quotedToken(
  source: string,
  start: number,
  line: number,
  column: number,
): { token: Token; next: number; column: number } | undefined {
  let index = start + 1;
  let value = "";
  let literal = true;
  let currentColumn = column + 1;
  while (index < source.length) {
    const character = source[index] ?? "";
    if (character === "\r" || character === "\n") return undefined;
    if (character === '"') {
      return {
        token: { kind: "string", value, line, column, literal },
        next: index + 1,
        column: currentColumn + 1,
      };
    }
    if ((character === "$" || character === "%") && source[index + 1] === "{") {
      literal = false;
    }
    if (character !== "\\") {
      value += character;
      index += 1;
      currentColumn += 1;
      continue;
    }
    const escaped = source[index + 1];
    if (escaped === undefined) return undefined;
    const simpleEscapes: Record<string, string> = {
      '"': '"',
      "\\": "\\",
      n: "\n",
      r: "\r",
      t: "\t",
    };
    if (simpleEscapes[escaped] !== undefined) {
      value += simpleEscapes[escaped];
      index += 2;
      currentColumn += 2;
      continue;
    }
    const digits = escaped === "u" ? 4 : escaped === "U" ? 8 : 0;
    const encoded = source.slice(index + 2, index + 2 + digits);
    if (
      digits > 0 &&
      new RegExp(`^[0-9A-Fa-f]{${digits}}$`, "u").test(encoded)
    ) {
      const codePoint = Number.parseInt(encoded, 16);
      if (
        codePoint <= 0x10ffff &&
        !(codePoint >= 0xd800 && codePoint <= 0xdfff)
      ) {
        value += String.fromCodePoint(codePoint);
        index += digits + 2;
        currentColumn += digits + 2;
        continue;
      }
    }
    literal = false;
    value += escaped;
    index += 2;
    currentColumn += 2;
  }
  return undefined;
}

function skipHeredoc(
  source: string,
  start: number,
  line: number,
  column: number,
): { token: Token; next: number; line: number; column: number } | undefined {
  const header = /^<<(-?)([A-Za-z_][A-Za-z0-9_-]*)[^\r\n]*(?:\r\n|\n|\r)/u.exec(
    source.slice(start),
  );
  if (header === null) return undefined;
  const indented = header[1] === "-";
  const marker = header[2] ?? "";
  let index = start + header[0].length;
  let currentLine = line + 1;
  while (index <= source.length) {
    const newline = /\r\n|\n|\r/gu;
    newline.lastIndex = index;
    const match = newline.exec(source);
    const end = match?.index ?? source.length;
    const candidate = source.slice(index, end);
    if ((indented ? candidate.trimStart() : candidate) === marker) {
      const next = match === null ? end : end + match[0].length;
      return {
        token: {
          kind: "string",
          value: "",
          line,
          column,
          literal: false,
        },
        next,
        line: match === null ? currentLine : currentLine + 1,
        column: 1,
      };
    }
    if (match === null) return undefined;
    index = end + match[0].length;
    currentLine += 1;
  }
  return undefined;
}

function tokenizeHcl(source: string): Token[] | undefined {
  const tokens: Token[] = [];
  let index = 0;
  let line = 1;
  let column = 1;
  while (index < source.length) {
    const character = source[index] ?? "";
    if (character === " " || character === "\t") {
      index += 1;
      column += 1;
      continue;
    }
    if (character === "\r" || character === "\n") {
      const width = character === "\r" && source[index + 1] === "\n" ? 2 : 1;
      tokens.push({
        kind: "newline",
        value: "\n",
        line,
        column,
        literal: true,
      });
      index += width;
      line += 1;
      column = 1;
      continue;
    }
    if (character === "#" || (character === "/" && source[index + 1] === "/")) {
      const end = source.slice(index).search(/[\r\n]/u);
      const width = end < 0 ? source.length - index : end;
      index += width;
      column += width;
      continue;
    }
    if (character === "/" && source[index + 1] === "*") {
      const commentLine = line;
      const end = source.indexOf("*/", index + 2);
      if (end < 0) return undefined;
      const comment = source.slice(index, end + 2);
      const rows = comment.split(/\r\n|\n|\r/u);
      if (rows.length === 1) {
        column += comment.length;
      } else {
        line += rows.length - 1;
        column = (rows.at(-1)?.length ?? 0) + 1;
        tokens.push({
          kind: "newline",
          value: "\n",
          line: commentLine,
          column: 1,
          literal: true,
        });
      }
      index = end + 2;
      continue;
    }
    if (character === '"') {
      const parsed = quotedToken(source, index, line, column);
      if (parsed === undefined) return undefined;
      tokens.push(parsed.token);
      index = parsed.next;
      column = parsed.column;
      continue;
    }
    if (character === "<" && source[index + 1] === "<") {
      const parsed = skipHeredoc(source, index, line, column);
      if (parsed === undefined) return undefined;
      tokens.push(parsed.token);
      tokens.push({
        kind: "newline",
        value: "\n",
        line: Math.max(line, parsed.line - 1),
        column: 1,
        literal: true,
      });
      index = parsed.next;
      line = parsed.line;
      column = parsed.column;
      continue;
    }
    if (isIdentifierStart(character)) {
      let end = index + 1;
      while (end < source.length && isIdentifierPart(source[end] ?? "")) {
        end += 1;
      }
      const value = source.slice(index, end);
      tokens.push({
        kind: "identifier",
        value,
        line,
        column,
        literal: true,
      });
      column += end - index;
      index = end;
      continue;
    }
    const number = /^-?\d+/u.exec(source.slice(index));
    if (number !== null) {
      tokens.push({
        kind: "number",
        value: number[0],
        line,
        column,
        literal: true,
      });
      index += number[0].length;
      column += number[0].length;
      continue;
    }
    if ("{}[]=,.():?+-*/!<>%&|~".includes(character)) {
      tokens.push({
        kind: "symbol",
        value: character,
        line,
        column,
        literal: true,
      });
      index += 1;
      column += 1;
      continue;
    }
    return undefined;
  }
  return tokens;
}

function matchingBrace(tokens: readonly Token[], open: number): number {
  let depth = 0;
  for (let index = open; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.kind !== "symbol") continue;
    if (token.value === "{") depth += 1;
    if (token.value === "}") {
      depth -= 1;
      if (depth === 0) return index;
      if (depth < 0) return -1;
    }
  }
  return -1;
}

function bodyItems(
  tokens: readonly Token[],
  start = 0,
  end = tokens.length,
  depth = 0,
): BodyItem[] | undefined {
  if (depth > MAX_HCL_NESTING) return undefined;
  const items: BodyItem[] = [];
  let index = start;
  while (index < end) {
    while (
      index < end &&
      (tokens[index]?.kind === "newline" ||
        (tokens[index]?.kind === "symbol" && tokens[index]?.value === ","))
    ) {
      index += 1;
    }
    if (index >= end) break;
    const name = tokens[index];
    if (name?.kind !== "identifier") return undefined;
    index += 1;
    const labels: Token[] = [];
    while (
      index < end &&
      (tokens[index]?.kind === "identifier" || tokens[index]?.kind === "string")
    ) {
      labels.push(tokens[index] as Token);
      index += 1;
    }
    const delimiter = tokens[index];
    if (delimiter?.kind !== "symbol") return undefined;
    if (delimiter.value === "{") {
      const close = matchingBrace(tokens, index);
      if (close < 0 || close >= end) return undefined;
      const nested = bodyItems(tokens, index + 1, close, depth + 1);
      if (nested === undefined) return undefined;
      items.push({
        kind: "block",
        name: name.value,
        line: name.line,
        labels,
        body: nested,
      });
      index = close + 1;
      continue;
    }
    if (delimiter.value !== "=" || labels.length > 0) return undefined;
    index += 1;
    const expression: Token[] = [];
    const stack: string[] = [];
    while (index < end) {
      const token = tokens[index] as Token;
      if (token.kind === "newline" && stack.length === 0) break;
      if (token.kind === "symbol") {
        if (token.value === "[" || token.value === "{" || token.value === "(") {
          stack.push(token.value);
        } else if (
          token.value === "]" ||
          token.value === "}" ||
          token.value === ")"
        ) {
          const expected =
            token.value === "]" ? "[" : token.value === "}" ? "{" : "(";
          if (stack.pop() !== expected) return undefined;
        } else if (token.value === "," && stack.length === 0) {
          break;
        }
      }
      expression.push(token);
      index += 1;
    }
    if (stack.length > 0 || expression.length === 0) return undefined;
    items.push({
      kind: "attribute",
      name: name.value,
      line: name.line,
      expression,
    });
  }
  return items;
}

function meaningful(tokens: readonly Token[]): Token[] {
  return tokens.filter((token) => token.kind !== "newline");
}

function literalString(
  attribute: AttributeItem | undefined,
): string | undefined {
  if (attribute === undefined) return undefined;
  const tokens = meaningful(attribute.expression);
  const token = tokens[0];
  return tokens.length === 1 && token?.kind === "string" && token.literal
    ? token.value
    : undefined;
}

function literalInteger(
  attribute: AttributeItem | undefined,
): number | undefined {
  if (attribute === undefined) return undefined;
  const tokens = meaningful(attribute.expression);
  const token = tokens[0];
  if (tokens.length !== 1 || token?.kind !== "number") return undefined;
  const value = Number(token.value);
  return Number.isSafeInteger(value) ? value : undefined;
}

function literalStringList(
  attribute: AttributeItem | undefined,
): Array<{ value: string; line: number }> | undefined {
  if (attribute === undefined) return undefined;
  const tokens = meaningful(attribute.expression);
  if (
    tokens[0]?.kind !== "symbol" ||
    tokens[0]?.value !== "[" ||
    tokens.at(-1)?.kind !== "symbol" ||
    tokens.at(-1)?.value !== "]"
  ) {
    return undefined;
  }
  const values: Array<{ value: string; line: number }> = [];
  let expectValue = true;
  for (const token of tokens.slice(1, -1)) {
    if (expectValue) {
      if (token.kind !== "string" || !token.literal) return undefined;
      values.push({ value: token.value, line: token.line });
      expectValue = false;
    } else {
      if (token.kind !== "symbol" || token.value !== ",") return undefined;
      expectValue = true;
    }
  }
  return values;
}

function uniqueAttributes(
  items: readonly BodyItem[],
): Map<string, AttributeItem> | undefined {
  const attributes = new Map<string, AttributeItem>();
  for (const item of items) {
    if (item.kind !== "attribute") continue;
    if (attributes.has(item.name)) return undefined;
    attributes.set(item.name, item);
  }
  return attributes;
}

function objectList(attribute: AttributeItem): BodyItem[][] | undefined {
  const tokens = attribute.expression;
  let outerStart = 0;
  let outerEnd = tokens.length;
  while (tokens[outerStart]?.kind === "newline") outerStart += 1;
  while (tokens[outerEnd - 1]?.kind === "newline") outerEnd -= 1;
  if (
    tokens[outerStart]?.kind !== "symbol" ||
    tokens[outerStart]?.value !== "[" ||
    tokens[outerEnd - 1]?.kind !== "symbol" ||
    tokens[outerEnd - 1]?.value !== "]"
  ) {
    return undefined;
  }
  const bodies: BodyItem[][] = [];
  let index = outerStart + 1;
  while (index < outerEnd - 1) {
    if (
      tokens[index]?.kind === "newline" ||
      (tokens[index]?.kind === "symbol" && tokens[index]?.value === ",")
    ) {
      index += 1;
      continue;
    }
    if (tokens[index]?.kind !== "symbol" || tokens[index]?.value !== "{") {
      return undefined;
    }
    const close = matchingBrace(tokens, index);
    if (close < 0 || close >= outerEnd - 1) return undefined;
    const body = bodyItems(tokens, index + 1, close);
    if (body === undefined) return undefined;
    bodies.push(body);
    index = close + 1;
  }
  return bodies;
}

function publicSources(
  attributes: ReadonlyMap<string, AttributeItem>,
): Array<{ value: string; line: number }> {
  const candidates: Array<{ value: string; line: number }> = [];
  for (const name of ["cidr_blocks", "ipv6_cidr_blocks"]) {
    const attribute = attributes.get(name);
    const values = literalStringList(attribute);
    if (values !== undefined) candidates.push(...values);
  }
  for (const name of ["cidr_ipv4", "cidr_ipv6"]) {
    const attribute = attributes.get(name);
    const value = literalString(attribute);
    if (value !== undefined && attribute !== undefined) {
      candidates.push({ value, line: attribute.line });
    }
  }
  return candidates.filter(({ value }) => PUBLIC_CIDRS.has(value));
}

function ingressRule(
  items: readonly BodyItem[],
  allProtocolRequiresOmittedPorts = false,
): LiteralIngressRule | undefined {
  const attributes = uniqueAttributes(items);
  if (attributes === undefined) return undefined;
  const sources = publicSources(attributes);
  if (sources.length === 0) return undefined;
  const protocolAttribute =
    attributes.get("ip_protocol") ?? attributes.get("protocol");
  const protocol =
    literalString(protocolAttribute) ??
    (literalInteger(protocolAttribute) === undefined
      ? undefined
      : String(literalInteger(protocolAttribute)));
  if (protocol === undefined) return undefined;
  const normalizedProtocol = protocol.toLowerCase();
  if (!["-1", "6", "17", "tcp", "udp"].includes(normalizedProtocol)) {
    return undefined;
  }
  const fromAttribute = attributes.get("from_port");
  const toAttribute = attributes.get("to_port");
  const fromPort = literalInteger(fromAttribute);
  const toPort = literalInteger(toAttribute);
  let retainedFromPort: number | "all";
  let retainedToPort: number | "all";
  let sinkLine: number;
  let administrationPorts: number[];
  if (normalizedProtocol === "-1") {
    if (allProtocolRequiresOmittedPorts) {
      if (fromAttribute !== undefined || toAttribute !== undefined)
        return undefined;
      retainedFromPort = "all";
      retainedToPort = "all";
      sinkLine = protocolAttribute?.line ?? sources[0]?.line ?? 1;
    } else {
      if (
        fromPort !== 0 ||
        toPort !== 0 ||
        fromAttribute === undefined ||
        toAttribute === undefined
      ) {
        return undefined;
      }
      retainedFromPort = fromPort;
      retainedToPort = toPort;
      sinkLine = fromAttribute.line;
    }
    administrationPorts = [...ADMINISTRATION_PORTS];
  } else {
    if (
      fromPort === undefined ||
      toPort === undefined ||
      fromAttribute === undefined ||
      toAttribute === undefined ||
      fromPort > toPort
    ) {
      return undefined;
    }
    retainedFromPort = fromPort;
    retainedToPort = toPort;
    sinkLine = fromAttribute.line;
    administrationPorts = ADMINISTRATION_PORTS.filter(
      (port) => port >= fromPort && port <= toPort,
    );
  }
  if (administrationPorts.length === 0) return undefined;
  const firstSource = [...sources].sort(
    (left, right) => left.line - right.line,
  )[0];
  if (firstSource === undefined) return undefined;
  return {
    sourceLine: firstSource.line,
    sinkLine,
    cidrs: [...new Set(sources.map(({ value }) => value))].sort(),
    protocol: normalizedProtocol,
    fromPort: retainedFromPort,
    toPort: retainedToPort,
    administrationPorts,
  };
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

function record(
  path: string,
  lines: readonly string[],
  resource: BlockItem,
  rule: LiteralIngressRule,
  shape:
    | "inline-attribute"
    | "inline-block"
    | "standalone-ingress-rule"
    | "standalone-rule",
): TerraformAwsPublicAdminIngressRecord {
  const resourceType = resource.labels[0]?.value ?? "";
  const resourceName = resource.labels[1]?.value ?? "";
  const resourceSymbol = `type=${resourceType};name=${resourceName}`;
  const sourceSymbol = `cidrs=${rule.cidrs.join(",")};direction=ingress`;
  const sinkSymbol = `protocol=${rule.protocol};fromPort=${rule.fromPort};toPort=${rule.toPort};administrationPorts=${rule.administrationPorts.join(",")}`;
  const sinkContext = contextExcerpt(lines, rule.sinkLine);
  const sourceContext = contextExcerpt(lines, rule.sourceLine);
  return {
    path,
    line: rule.sinkLine,
    categories: ["terraform-aws-public-admin-ingress"],
    priority: 100,
    startLine: sinkContext.startLine,
    endLine: sinkContext.endLine,
    excerpt: sinkContext.excerpt,
    sourceExcerpt: sourceContext.excerpt,
    frameworkModel: {
      schemaVersion: "1.2",
      id: "terraform-aws-public-admin-ingress",
      language: "terraform-hcl",
      scope: "same-file",
      source: {
        kind: "unrestricted-ipv4-or-ipv6-ingress",
        path,
        line: rule.sourceLine,
        symbol: sourceSymbol,
      },
      sink: {
        kind: "remote-administration-port-ingress",
        path,
        line: rule.sinkLine,
        symbol: sinkSymbol,
        cweIds: ["CWE-284", "CWE-668"],
      },
      propagators: [
        {
          kind: "terraform-aws-security-group-resource",
          path,
          line: resource.line,
          symbol: resourceSymbol,
        },
        {
          kind: "literal-ingress-rule",
          path,
          line: Math.min(rule.sourceLine, rule.sinkLine),
          symbol: `${resourceSymbol};shape=${shape};${sourceSymbol};${sinkSymbol}`,
        },
      ],
      candidateControls: [],
    },
  };
}

function resourceRecords(
  path: string,
  lines: readonly string[],
  resource: BlockItem,
): TerraformAwsPublicAdminIngressRecord[] {
  if (
    resource.labels.length !== 2 ||
    resource.labels.some((label) => label.kind !== "string" || !label.literal)
  ) {
    return [];
  }
  const resourceType = resource.labels[0]?.value;
  const records: TerraformAwsPublicAdminIngressRecord[] = [];
  if (resourceType === "aws_security_group") {
    for (const ingress of resource.body.filter(
      (item): item is BlockItem =>
        item.kind === "block" && item.name === "ingress",
    )) {
      const rule = ingressRule(ingress.body);
      if (rule !== undefined)
        records.push(record(path, lines, resource, rule, "inline-block"));
    }
    const attributes = uniqueAttributes(resource.body);
    const ingressAttribute = attributes?.get("ingress");
    if (ingressAttribute !== undefined) {
      const bodies = objectList(ingressAttribute);
      if (bodies !== undefined) {
        for (const body of bodies) {
          const rule = ingressRule(body);
          if (rule !== undefined) {
            records.push(
              record(path, lines, resource, rule, "inline-attribute"),
            );
          }
        }
      }
    }
    return records;
  }
  if (resourceType === "aws_security_group_rule") {
    const attributes = uniqueAttributes(resource.body);
    if (
      attributes === undefined ||
      literalString(attributes.get("type")) !== "ingress"
    ) {
      return [];
    }
    const rule = ingressRule(resource.body);
    return rule === undefined
      ? []
      : [record(path, lines, resource, rule, "standalone-rule")];
  }
  if (resourceType === "aws_vpc_security_group_ingress_rule") {
    const rule = ingressRule(resource.body, true);
    return rule === undefined
      ? []
      : [record(path, lines, resource, rule, "standalone-ingress-rule")];
  }
  return [];
}

export function terraformRiskRecords(
  path: string,
  lines: readonly string[],
  source: string,
): TerraformAwsPublicAdminIngressRecord[] {
  if (!/\.tf$/iu.test(path)) return [];
  const tokens = tokenizeHcl(source);
  if (tokens === undefined || tokens.length > MAX_HCL_TOKENS) return [];
  const items = bodyItems(tokens);
  if (items === undefined) return [];
  const resources = items.filter(
    (item): item is BlockItem =>
      item.kind === "block" && item.name === "resource",
  );
  return resources.flatMap((resource) =>
    resourceRecords(path, lines, resource),
  );
}
