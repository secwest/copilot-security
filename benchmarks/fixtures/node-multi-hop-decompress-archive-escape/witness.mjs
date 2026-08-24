import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import decompress from "@xhmikosr/decompress";

const metadata = JSON.parse(
  await readFile(
    new URL(
      "./node_modules/@xhmikosr/decompress/package.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const root = await mkdtemp(join(tmpdir(), "decompress-archive-escape-"));
const output = join(root, "out");
const sibling = join(root, "out-sibling");
const escapedPath = join(sibling, "escaped.txt");

try {
  await mkdir(output);
  await mkdir(sibling);
  const plugin = () => [
    {
      type: "file",
      path: "../out-sibling/escaped.txt",
      mode: 0o644,
      mtime: new Date(0),
      data: Buffer.from("bounded-sentinel"),
    },
  ];
  let error = null;
  try {
    await decompress(Buffer.from("archive-placeholder"), output, {
      plugins: [plugin],
    });
  } catch (caught) {
    error = caught instanceof Error ? caught.message : String(caught);
  }
  const escaped =
    (await readFile(escapedPath, "utf8").catch(() => null)) ===
    "bounded-sentinel";
  const expectedEscape = metadata.version === "10.2.0";
  if (escaped !== expectedEscape) {
    throw new Error(
      `Unexpected archive boundary for ${metadata.version}: escaped=${escaped}, error=${error}`,
    );
  }
  console.log(JSON.stringify({ version: metadata.version, escaped, error }));
} finally {
  await rm(root, { recursive: true, force: true });
}
