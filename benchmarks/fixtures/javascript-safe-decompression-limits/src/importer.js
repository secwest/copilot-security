import { inflateRawSync } from "node:zlib";

const SAFE_ENTRY_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const MAX_BUNDLE_ENTRIES = 128;
const MAX_COMPRESSED_ENTRY_BYTES = 2 * 1024 * 1024;
const MAX_COMPRESSED_BUNDLE_BYTES = 4 * 1024 * 1024;
const MAX_EXPANDED_ENTRY_BYTES = 2 * 1024 * 1024;
const MAX_EXPANDED_BUNDLE_BYTES = 4 * 1024 * 1024;
const MAX_EXPANSION_RATIO = 100;

export function importBundle(entries, storage) {
  if (!Array.isArray(entries)) {
    throw new Error("bundle entries must be an array");
  }
  const entryCount = entries.length;
  if (entryCount > MAX_BUNDLE_ENTRIES) {
    throw new Error("bundle entry count exceeds limit");
  }
  const names = new Set();
  const staged = [];
  let compressedTotal = 0;
  let expandedTotal = 0;

  for (let index = 0; index < entryCount; index += 1) {
    const entry = entries[index];
    if (entry === null || typeof entry !== "object") {
      throw new Error("invalid bundle entry");
    }
    const { name, compressed, uncompressedSize } = entry;
    validateEntry(name, compressed, uncompressedSize, expandedTotal);
    if (names.has(name)) {
      throw new Error("duplicate bundle entry name");
    }
    names.add(name);
    compressedTotal += compressed.byteLength;
    if (compressedTotal > MAX_COMPRESSED_BUNDLE_BYTES) {
      throw new Error("bundle exceeds cumulative compressed-input limit");
    }
    const compressedSnapshot = Buffer.from(compressed);
    const remaining = MAX_EXPANDED_BUNDLE_BYTES - expandedTotal;
    const outputLimit = Math.min(MAX_EXPANDED_ENTRY_BYTES, remaining);
    let expanded;
    try {
      expanded = inflateRawSync(compressedSnapshot, {
        maxOutputLength: outputLimit + 1,
      });
    } catch (error) {
      throw new Error(
        "compressed entry is invalid or exceeds decompression limits",
        { cause: error },
      );
    }

    if (expanded.byteLength > MAX_EXPANDED_ENTRY_BYTES) {
      throw new Error("decompressed entry exceeds size limit");
    }
    if (expanded.byteLength > remaining) {
      throw new Error("bundle exceeds cumulative decompression limit");
    }
    if (expanded.byteLength !== uncompressedSize) {
      throw new Error("declared and actual decompressed sizes differ");
    }
    if (
      expanded.byteLength >
      Math.max(1, compressedSnapshot.byteLength) * MAX_EXPANSION_RATIO
    ) {
      throw new Error("decompression expansion ratio exceeds limit");
    }

    expandedTotal += expanded.byteLength;
    staged.push({ name, expanded });
  }

  for (let index = 0; index < staged.length; index += 1) {
    const { name, expanded } = staged[index];
    storage.put(name, expanded);
  }
}

function validateEntry(name, compressed, uncompressedSize, expandedTotal) {
  if (typeof name !== "string" || !SAFE_ENTRY_NAME.test(name)) {
    throw new Error("invalid bundle entry name");
  }
  if (!Buffer.isBuffer(compressed)) {
    throw new Error("compressed entry must be a Buffer");
  }
  if (compressed.byteLength > MAX_COMPRESSED_ENTRY_BYTES) {
    throw new Error("compressed entry exceeds size limit");
  }
  if (
    !Number.isSafeInteger(uncompressedSize) ||
    uncompressedSize < 0 ||
    uncompressedSize > MAX_EXPANDED_ENTRY_BYTES
  ) {
    throw new Error("invalid declared decompressed size");
  }
  if (uncompressedSize > MAX_EXPANDED_BUNDLE_BYTES - expandedTotal) {
    throw new Error("bundle exceeds cumulative decompression limit");
  }
}
