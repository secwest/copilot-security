import { posix as path, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";

type ArchiveEntry =
  | { type: "directory"; name: string }
  | { type: "file"; name: string; data: string }
  | { type: "symlink" | "hardlink"; name: string; linkName: string };

interface Fixture {
  extractArchive(
    destination: string,
    entries: ArchiveEntry[],
    filesystem: ArchiveFilesystem,
  ): void;
}

interface ArchiveFilesystem {
  mkdir(target: string): void;
  symlink(linkName: string, target: string): void;
  hardlink(existing: string, target: string): void;
  writeFile(target: string, data: string): void;
  mkdirNoFollow(root: string, target: string): void;
  writeFileNoFollow(root: string, target: string, data: string): void;
}

type Node =
  | { type: "directory" }
  | { type: "file"; data: string }
  | { type: "symlink" | "hardlink"; target: string };

const EXTRACTION_ROOT = "/service/imports";
const POLICY = "/service/trusted/config/policy.json";
const ORIGINAL_POLICY = '{"allowGuestAdmin":false}';
const ATTACKER_POLICY = '{"allowGuestAdmin":true}';

describe("archive link-pivot benchmark", () => {
  test("a contained member writes through an earlier archive symlink", async () => {
    const fixture = await loadFixture("javascript-archive-link-pivot");
    const filesystem = seededFilesystem();

    fixture.extractArchive(
      EXTRACTION_ROOT,
      [
        {
          type: "symlink",
          name: "staging/config",
          linkName: "../../trusted/config",
        },
        {
          type: "file",
          name: "staging/config/policy.json",
          data: ATTACKER_POLICY,
        },
        { type: "file", name: "docs/readme.txt", data: "ordinary import" },
      ],
      filesystem,
    );

    expect(filesystem.readFile(POLICY)).toBe(ATTACKER_POLICY);
    expect(filesystem.readFile("/service/imports/docs/readme.txt")).toBe(
      "ordinary import",
    );
  });

  test("an archive hardlink aliases a trusted file before a later write", async () => {
    const fixture = await loadFixture("javascript-archive-link-pivot");
    const filesystem = seededFilesystem();

    fixture.extractArchive(
      EXTRACTION_ROOT,
      [
        {
          type: "hardlink",
          name: "staging/policy.json",
          linkName: "../trusted/config/policy.json",
        },
        {
          type: "file",
          name: "staging/policy.json",
          data: ATTACKER_POLICY,
        },
      ],
      filesystem,
    );

    expect(filesystem.readFile(POLICY)).toBe(ATTACKER_POLICY);
  });

  test("link rejection and root-anchored no-follow writes preserve trusted files", async () => {
    const fixture = await loadFixture("javascript-safe-archive-link-isolation");
    const filesystem = seededFilesystem();
    expect(() =>
      fixture.extractArchive(
        EXTRACTION_ROOT,
        [
          {
            type: "symlink",
            name: "staging/config",
            linkName: "../../trusted/config",
          },
        ],
        filesystem,
      ),
    ).toThrow("archive links are not allowed");
    expect(filesystem.readFile(POLICY)).toBe(ORIGINAL_POLICY);

    filesystem.mkdir("/service/imports/staging");
    filesystem.symlink(
      "../../trusted/config",
      "/service/imports/staging/config",
    );
    expect(() =>
      fixture.extractArchive(
        EXTRACTION_ROOT,
        [
          {
            type: "file",
            name: "staging/config/policy.json",
            data: ATTACKER_POLICY,
          },
        ],
        filesystem,
      ),
    ).toThrow("archive path traverses a link");
    expect(filesystem.readFile(POLICY)).toBe(ORIGINAL_POLICY);

    const legitimate = seededFilesystem();
    fixture.extractArchive(
      EXTRACTION_ROOT,
      [
        { type: "directory", name: "docs" },
        { type: "file", name: "docs/readme.txt", data: "ordinary import" },
      ],
      legitimate,
    );
    expect(legitimate.readFile("/service/imports/docs/readme.txt")).toBe(
      "ordinary import",
    );
    expect(legitimate.readFile(POLICY)).toBe(ORIGINAL_POLICY);
  });
});

class VirtualArchiveFilesystem implements ArchiveFilesystem {
  readonly #nodes = new Map<string, Node>();

  constructor() {
    this.#nodes.set("/", { type: "directory" });
  }

  mkdir(target: string): void {
    const normalized = path.resolve("/", target);
    const components = normalized.split("/").filter(Boolean);
    let current = "/";
    for (const component of components) {
      current = this.#resolve(`${current}/${component}`);
      const node = this.#nodes.get(current);
      if (node === undefined) this.#nodes.set(current, { type: "directory" });
      else if (node.type !== "directory") throw new Error("not a directory");
    }
  }

  symlink(linkName: string, target: string): void {
    this.#nodes.set(path.resolve("/", target), {
      type: "symlink",
      target: linkName,
    });
  }

  hardlink(existing: string, target: string): void {
    const source = this.#resolve(path.resolve("/", existing));
    if (this.#nodes.get(source)?.type !== "file") {
      throw new Error("hardlink source is not a file");
    }
    this.#nodes.set(path.resolve("/", target), {
      type: "hardlink",
      target: source,
    });
  }

  writeFile(target: string, data: string): void {
    const resolved = this.#resolve(path.resolve("/", target));
    this.mkdir(path.dirname(resolved));
    this.#nodes.set(resolved, { type: "file", data });
  }

  mkdirNoFollow(root: string, target: string): void {
    this.#assertNoLinks(root, target);
    this.mkdir(target);
  }

  writeFileNoFollow(root: string, target: string, data: string): void {
    this.#assertNoLinks(root, target);
    const normalized = path.resolve("/", target);
    this.#nodes.set(normalized, { type: "file", data });
  }

  seedFile(target: string, data: string): void {
    this.mkdir(path.dirname(target));
    this.#nodes.set(path.resolve("/", target), { type: "file", data });
  }

  readFile(target: string): string {
    const node = this.#nodes.get(this.#resolve(path.resolve("/", target)));
    if (node?.type !== "file") throw new Error("not a file");
    return node.data;
  }

  #assertNoLinks(root: string, target: string): void {
    const normalizedRoot = path.resolve("/", root);
    const normalizedTarget = path.resolve("/", target);
    if (
      normalizedTarget !== normalizedRoot &&
      !normalizedTarget.startsWith(`${normalizedRoot}/`)
    ) {
      throw new Error("archive path escapes extraction root");
    }
    const relative = path.relative(normalizedRoot, normalizedTarget);
    let current = normalizedRoot;
    for (const component of relative.split("/").filter(Boolean)) {
      current = path.join(current, component);
      const node = this.#nodes.get(current);
      if (node?.type === "symlink" || node?.type === "hardlink") {
        throw new Error("archive path traverses a link");
      }
    }
  }

  #resolve(target: string, depth = 0): string {
    if (depth > 32) throw new Error("too many links");
    const normalized = path.resolve("/", target);
    const components = normalized.split("/").filter(Boolean);
    let current = "/";
    for (let index = 0; index < components.length; index += 1) {
      current = path.join(current, components[index]!);
      const node = this.#nodes.get(current);
      if (node?.type !== "symlink" && node?.type !== "hardlink") continue;
      const destination =
        node.type === "hardlink" || path.isAbsolute(node.target)
          ? node.target
          : path.resolve(path.dirname(current), node.target);
      return this.#resolve(
        path.join(destination, ...components.slice(index + 1)),
        depth + 1,
      );
    }
    return current;
  }
}

function seededFilesystem(): VirtualArchiveFilesystem {
  const filesystem = new VirtualArchiveFilesystem();
  filesystem.seedFile(POLICY, ORIGINAL_POLICY);
  filesystem.mkdir(EXTRACTION_ROOT);
  return filesystem;
}

async function loadFixture(name: string): Promise<Fixture> {
  const source = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    name,
    "src",
    "extractor.js",
  );
  return (await import(pathToFileURL(source).href)) as Fixture;
}
