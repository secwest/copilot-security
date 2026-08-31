import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

async function scanAngularSource(
  source: string,
  options: {
    dependencySection?: "dependencies" | "devDependencies";
    sourcePath?: string;
    version?: string;
  } = {},
): Promise<any[]> {
  const repository = await mkdtemp(join(tmpdir(), "angular-message-origin-"));
  temporaryPaths.push(repository);
  await mkdir(join(repository, "src"));
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      private: true,
      [options.dependencySection ?? "dependencies"]: {
        "@angular/core": options.version ?? "20.0.0",
      },
    }),
  );
  const sourcePath = options.sourcePath ?? "message.component.ts";
  await writeFile(join(repository, "src", sourcePath), source);
  return (await buildResidualRiskInventory(repository))
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-angular-host-listener-missing-origin-check",
    );
}

describe("Angular HostListener message-origin model", () => {
  test("keeps the versioned vulnerable and exact-origin fixtures paired", async () => {
    const fixtureRoot = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
    );
    const vulnerable = (
      await buildResidualRiskInventory(
        join(fixtureRoot, "node-angular-host-listener-missing-origin-check"),
      )
    )
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .filter(
        (record) =>
          record.frameworkModel?.id ===
          "node-angular-host-listener-missing-origin-check",
      );
    const control = (
      await buildResidualRiskInventory(
        join(fixtureRoot, "node-angular-host-listener-exact-origin-check"),
      )
    )
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .filter(
        (record) =>
          record.frameworkModel?.id ===
          "node-angular-host-listener-missing-origin-check",
      );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      source: { kind: "angular-postmessage-event", line: 8 },
      sink: {
        kind: "message-payload-use-without-sender-authorization",
        line: 9,
        cweIds: ["CWE-20", "CWE-940"],
      },
      propagators: expect.arrayContaining([
        expect.objectContaining({ kind: "angular-host-listener-binding" }),
        expect.objectContaining({ kind: "angular-active-class-decorator" }),
        expect.objectContaining({
          kind: "angular-global-message-listener",
          symbol: "window:message",
        }),
        expect.objectContaining({
          kind: "angular-runtime-dependency",
          symbol: "@angular/core@20.0.0:manifest-exact",
        }),
      ]),
    });
    expect(control).toHaveLength(0);
  });

  test("distinguishes a used message payload from an exact origin guard", async () => {
    const vulnerable = await scanAngularSource(
      [
        'import { Component, HostListener } from "@angular/core";',
        '@Component({ selector: "app-message", template: "" })',
        "export class MessageComponent {",
        '  @HostListener("window:message", ["$event"])',
        "  handleMessage(event: MessageEvent) {",
        "    this.lastAction = event.data.action;",
        "  }",
        "}",
      ].join("\n"),
    );
    const control = await scanAngularSource(
      [
        'import { Component, HostListener } from "@angular/core";',
        '@Component({ selector: "app-message", template: "" })',
        "export class MessageComponent {",
        '  @HostListener("window:message", ["$event"])',
        "  handleMessage(event: MessageEvent) {",
        '    if (event.origin !== "https://portal.example") return;',
        "    this.lastAction = event.data.action;",
        "  }",
        "}",
      ].join("\n"),
    );

    expect(vulnerable).toHaveLength(1);
    expect(control).toHaveLength(0);
  });

  test("supports aliased directives and document message payloads", async () => {
    const found = await scanAngularSource(
      [
        'import { Directive as Active, HostListener as Listen } from "@angular/core";',
        '@Active({ selector: "[messageBridge]" })',
        "export class MessageBridge {",
        '  @Listen("document:message", ["$event"])',
        "  receive(message: MessageEvent) {",
        '    this.command = message["data"];',
        "  }",
        "}",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { kind: "angular-postmessage-event", line: 5 },
      sink: {
        kind: "message-payload-use-without-sender-authorization",
        line: 6,
        cweIds: ["CWE-20", "CWE-940"],
      },
    });
  });

  test("credits exact positive origin and source-identity authorization", async () => {
    const origin = await scanAngularSource(
      [
        'import { Component, HostListener } from "@angular/core";',
        '@Component({ selector: "app-message", template: "" })',
        "export class MessageComponent {",
        '  @HostListener("window:message", ["$event"])',
        "  handleMessage(event: MessageEvent) {",
        '    if (event.origin === "https://portal.example") {',
        "      this.lastAction = event.data.action;",
        "    }",
        "  }",
        "}",
      ].join("\n"),
    );
    const source = await scanAngularSource(
      [
        'import { Component, HostListener } from "@angular/core";',
        '@Component({ selector: "app-message", template: "" })',
        "export class MessageComponent {",
        '  @HostListener("window:message", ["$event"])',
        "  handleMessage(event: MessageEvent) {",
        "    if (event.source !== window.parent) return;",
        "    this.lastAction = event.data.action;",
        "  }",
        "}",
      ].join("\n"),
    );
    expect(origin).toHaveLength(0);
    expect(source).toHaveLength(0);
  });

  test("credits multiline rejection guards and explicit default ports", async () => {
    const origin = await scanAngularSource(
      [
        'import { Component, HostListener } from "@angular/core";',
        '@Component({ selector: "app-message", template: "" })',
        "export class MessageComponent {",
        '  @HostListener("window:message", ["$event"])',
        "  handleMessage(event: MessageEvent) {",
        '    if (event.origin !== "https://portal.example:443") {',
        "      return;",
        "    }",
        "    this.lastAction = event.data.action;",
        "  }",
        "}",
      ].join("\n"),
    );
    const source = await scanAngularSource(
      [
        'import { Directive, HostListener } from "@angular/core";',
        '@Directive({ selector: "[messageBridge]" })',
        "export class MessageBridge {",
        '  @HostListener("document:message", ["$event"])',
        "  receive(event: MessageEvent) {",
        "    if (event.source !== globalThis.opener) {",
        "      throw new Error('unexpected sender');",
        "    }",
        "    this.lastAction = event.data.action;",
        "  }",
        "}",
      ].join("\n"),
    );
    expect(origin).toHaveLength(0);
    expect(source).toHaveLength(0);
  });

  test("requires the listener method to belong to the activated Angular class", async () => {
    const found = await scanAngularSource(
      [
        'import { Component, HostListener } from "@angular/core";',
        "@Component({",
        '  selector: "app-active",',
        '  template: ""',
        "})",
        "export class ActiveComponent {}",
        "export class InactiveMessageBridge {",
        '  @HostListener("window:message", ["$event"])',
        "  handleMessage(event: MessageEvent) {",
        "    this.lastAction = event.data.action;",
        "  }",
        "}",
      ].join("\n"),
    );
    expect(found).toHaveLength(0);
  });

  test("keeps weak and post-use origin checks reportable", async () => {
    const weak = await scanAngularSource(
      [
        'import { Component, HostListener } from "@angular/core";',
        '@Component({ selector: "app-message", template: "" })',
        "export class MessageComponent {",
        '  @HostListener("window:message", ["$event"])',
        "  handleMessage(event: MessageEvent) {",
        '    if (!event.origin.endsWith("example")) return;',
        "    this.lastAction = event.data.action;",
        "  }",
        "}",
      ].join("\n"),
    );
    const late = await scanAngularSource(
      [
        'import { Component, HostListener } from "@angular/core";',
        '@Component({ selector: "app-message", template: "" })',
        "export class MessageComponent {",
        '  @HostListener("window:message", ["$event"])',
        "  handleMessage(event: MessageEvent) {",
        "    this.lastAction = event.data.action;",
        '    if (event.origin !== "https://portal.example") return;',
        "  }",
        "}",
      ].join("\n"),
    );
    expect(weak).toHaveLength(1);
    expect(late).toHaveLength(1);
  });

  test("requires Angular sender-boundary and CWE evidence in both narratives", async () => {
    const repository = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
      "node-angular-host-listener-missing-origin-check",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "angular-origin-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_angular_host_listener_origin_quality",
      taxonomy: { cwe: ["CWE-20", "CWE-940"] },
      locations: [
        { path: "src/message.component.ts", startLine: 8, role: "source" },
        { path: "src/message.component.ts", startLine: 9, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "angular-message-source",
          path: "src/message.component.ts",
          startLine: 8,
          code: "handleMessage(event: MessageEvent) {",
          explanation: "Global Angular message event parameter.",
          role: "source",
        },
        {
          id: "angular-message-payload",
          path: "src/message.component.ts",
          startLine: 9,
          code: "this.lastAction = event.data.action;",
          explanation: "Message payload use.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A message payload is used.",
        method: "source review",
        evidence: ["angular-message-source", "angular-message-payload"],
      },
      attackPath: {
        summary: "A message payload is used.",
        dataflow: {
          source: "angular-message-source",
          sink: "angular-message-payload",
          outcome: "message handling",
        },
        evidenceRefs: ["angular-message-source", "angular-message-payload"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    expect(incomplete).toContain("missing_model_specific_validation_evidence");
    expect(incomplete).toContain("missing_model_specific_attack_path_evidence");

    const contract =
      "Angular 20 at @angular/core@20.0.0 supplies the official HostListener on an active Component and binds the global window:message event. The exact $event MessageEvent parameter supplies remote message data through event.data before any exact trusted event.origin comparison or stable event.source sender identity authorization. A reachable cross-origin iframe window can send the payload; this missing origin verification is CWE-20 and CWE-940.";
    finding.validation.summary = contract;
    finding.attackPath.summary = contract;
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const complete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    expect(complete).not.toContain(
      "missing_model_specific_validation_evidence",
    );
    expect(complete).not.toContain(
      "missing_model_specific_attack_path_evidence",
    );
  });

  test("teaches the reviewer the exact Angular sender boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-angular-host-listener-missing-origin-check"}}',
    );
    expect(prompt).toContain("node-angular-host-listener-missing-origin-check");
    expect(prompt).toContain("production @angular/core dependency");
    expect(prompt).toContain("window:message");
    expect(prompt).toContain("exact $event argument mapping");
    expect(prompt).toContain("event.data");
    expect(prompt).toContain("event.origin");
    expect(prompt).toContain("parent/opener");
    expect(prompt).toContain("CWE-20/CWE-940");
    expect(prompt).toContain("code execution");
  });

  test("rejects dependency, activation, event-mapping, and payload lookalikes", async () => {
    const source = [
      'import { Component, HostListener } from "@angular/core";',
      '@Component({ selector: "app-message", template: "" })',
      "export class MessageComponent {",
      '  @HostListener("window:message", ["$event"])',
      "  handleMessage(event: MessageEvent) {",
      "    this.lastAction = event.data.action;",
      "  }",
      "}",
    ].join("\n");
    expect(
      await scanAngularSource(source, { version: "^20.0.0" }),
    ).toHaveLength(0);
    expect(
      await scanAngularSource(source, { dependencySection: "devDependencies" }),
    ).toHaveLength(0);
    expect(
      await scanAngularSource(source, {
        sourcePath: "message.component.test.ts",
      }),
    ).toHaveLength(0);
    expect(
      await scanAngularSource(
        source.replace(
          '@Component({ selector: "app-message", template: "" })',
          "",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scanAngularSource(source.replace('["$event"]', '["$event.data"]')),
    ).toHaveLength(0);
    expect(
      await scanAngularSource(
        source.replace("event.data.action", "event.type"),
      ),
    ).toHaveLength(0);
  });
});
