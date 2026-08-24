import { gzipSync } from "node:zlib";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";

function octal(value, width) {
  return `${value.toString(8).padStart(width - 1, "0")}\0`;
}

function tarHeader(name, size) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  header.write(octal(0o600, 8), 100, 8, "ascii");
  header.write(octal(0, 8), 108, 8, "ascii");
  header.write(octal(0, 8), 116, 8, "ascii");
  header.write(octal(size, 12), 124, 12, "ascii");
  header.write(octal(0, 12), 136, 12, "ascii");
  header.fill(0x20, 148, 156);
  header.write("0", 156, 1, "ascii");
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  return header;
}

const payload = Buffer.alloc(8 * 1024 * 1024);
const padding = Buffer.alloc((512 - (payload.length % 512)) % 512);
const archive = Buffer.concat([
  tarHeader("bounded-zero-payload", payload.length),
  payload,
  padding,
  Buffer.alloc(1024),
]);
const compressed = gzipSync(archive, { level: 9 });
const directory = await mkdtemp(join(tmpdir(), "copilot-security-tar-ratio-"));
const archivePath = join(directory, "bounded-bomb.tgz");
let blocked = false;
let errorMessage = "";
try {
  await writeFile(archivePath, compressed);
  try {
    await tar.list({ file: archivePath });
  } catch (error) {
    errorMessage = error instanceof Error ? error.message : String(error);
    blocked = /max decompression ratio exceeded/iu.test(errorMessage);
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
const packageJson = JSON.parse(
  await readFile(new URL("./node_modules/tar/package.json", import.meta.url), "utf8"),
);
const vulnerable = packageJson.version === "7.5.18";
if ((vulnerable && blocked) || (!vulnerable && !blocked)) {
  throw new Error(
    `unexpected decompression guard result for tar ${packageJson.version}: ${errorMessage || "completed"}`,
  );
}
console.log(
  JSON.stringify({
    version: packageJson.version,
    compressedBytes: compressed.length,
    decompressedBytes: archive.length,
    ratio: Number((archive.length / compressed.length).toFixed(2)),
    blocked,
    errorMessage,
  }),
);
