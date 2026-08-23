import { describe, expect, test } from "bun:test";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strToU8, zipSync } from "fflate";
import { extractPluginZip } from "../src/runtime.js";

const CENTRAL_FILE_HEADER = 0x02014b50;

function pluginManifest(): Uint8Array {
  return strToU8(
    `${JSON.stringify({ name: "copilot-security", version: "test" })}\n`,
  );
}

function markZipEntryAsSymlink(
  archive: Uint8Array,
  expectedName: string,
): Uint8Array {
  const patched = Buffer.from(archive);
  for (let offset = 0; offset + 46 <= patched.byteLength; offset += 1) {
    if (patched.readUInt32LE(offset) !== CENTRAL_FILE_HEADER) continue;
    const nameLength = patched.readUInt16LE(offset + 28);
    const extraLength = patched.readUInt16LE(offset + 30);
    const commentLength = patched.readUInt16LE(offset + 32);
    const nameStart = offset + 46;
    const name = patched.subarray(nameStart, nameStart + nameLength).toString();
    if (name === expectedName) {
      patched.writeUInt16LE(0x0314, offset + 4);
      patched.writeUInt32LE((0o120777 << 16) >>> 0, offset + 38);
      return patched;
    }
    offset = nameStart + nameLength + extraLength + commentLength - 1;
  }
  throw new Error(`missing ZIP entry: ${expectedName}`);
}

describe("plugin ZIP extraction security", () => {
  test("extracts a valid plugin through exclusive regular-file writes", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-plugin-zip-valid-"));
    const archive = join(root, "plugin.zip");
    const destination = join(root, "installed");
    try {
      await writeFile(
        archive,
        zipSync({
          "plugin.json": pluginManifest(),
          "agents/security-review.md": strToU8("scan defensively\n"),
        }),
      );

      const pluginRoot = await extractPluginZip(archive, destination);

      expect(pluginRoot).toBe(destination);
      expect(
        await readFile(
          join(pluginRoot, "agents", "security-review.md"),
          "utf8",
        ),
      ).toBe("scan defensively\n");
      const extracted = await lstat(join(pluginRoot, "plugin.json"));
      expect(extracted.isFile()).toBeTrue();
      expect(extracted.isSymbolicLink()).toBeFalse();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects an archive symlink before extracting any regular member", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-plugin-zip-link-"));
    const archive = join(root, "plugin.zip");
    const destination = join(root, "installed");
    const outside = join(root, "outside.txt");
    try {
      await writeFile(outside, "host-owned\n");
      const malicious = markZipEntryAsSymlink(
        zipSync({
          "plugin.json": pluginManifest(),
          link: strToU8("../../outside.txt"),
        }),
        "link",
      );
      await writeFile(archive, malicious);

      await expect(extractPluginZip(archive, destination)).rejects.toThrow(
        "Plugin ZIP contains an unsafe path: link",
      );

      expect(await readFile(outside, "utf8")).toBe("host-owned\n");
      expect(await lstat(destination).catch(() => null)).toBeNull();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects traversal, raw backslashes, and file-child conflicts", async () => {
    const cases: Array<{ name: string; entries: Record<string, Uint8Array> }> =
      [
        {
          name: "parent traversal",
          entries: {
            "plugin.json": pluginManifest(),
            "../outside.txt": strToU8("outside\n"),
          },
        },
        {
          name: "backslash traversal",
          entries: {
            "plugin.json": pluginManifest(),
            "..\\outside.txt": strToU8("outside\n"),
          },
        },
        {
          name: "file-child conflict",
          entries: {
            "plugin.json": pluginManifest(),
            agents: strToU8("regular file\n"),
            "agents/review.md": strToU8("child\n"),
          },
        },
      ];

    for (const item of cases) {
      const root = await mkdtemp(join(tmpdir(), "copilot-plugin-zip-path-"));
      try {
        const archive = join(root, "plugin.zip");
        const destination = join(root, "installed");
        await writeFile(archive, zipSync(item.entries));

        await expect(extractPluginZip(archive, destination)).rejects.toThrow();
        expect(
          await lstat(destination).catch(() => null),
          item.name,
        ).toBeNull();
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });
});
