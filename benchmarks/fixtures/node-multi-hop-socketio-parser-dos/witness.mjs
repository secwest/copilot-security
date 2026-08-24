import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Decoder } from "socket.io-parser";

const manifest = JSON.parse(
  await readFile(new URL("package.json", import.meta.url)),
);
const version = manifest.dependencies["socket.io-parser"];
const decoder = new Decoder();
const frameCount = 2_048;
const frameBytes = 4_096;
let decoded = 0;
let initialError;

decoder.on("decoded", () => {
  decoded += 1;
});

try {
  decoder.add('50-["evt"]');
} catch (error) {
  initialError = error;
}

if (initialError === undefined) {
  for (let index = 0; index < frameCount; index += 1) {
    decoder.add(Buffer.alloc(frameBytes, index & 0xff));
  }
}

const retainedFrames = decoder.reconstructor?.buffers?.length ?? 0;
if (version === "4.2.6") {
  assert.equal(initialError, undefined);
  assert.equal(decoded, 1);
  assert.equal(retainedFrames, frameCount);
} else {
  assert.equal(version, "4.2.7");
  assert.match(String(initialError), /Illegal attachments/u);
  assert.equal(decoded, 0);
  assert.equal(retainedFrames, 0);
}

decoder.destroy();
console.log(
  `${version} retained ${retainedFrames} frames (${retainedFrames * frameBytes} bytes)`,
);
