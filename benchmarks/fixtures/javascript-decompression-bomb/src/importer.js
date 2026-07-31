import { inflateRawSync } from "node:zlib";

const SAFE_ENTRY_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/u;

export function importBundle(entries, storage) {
  for (const entry of entries) {
    if (!SAFE_ENTRY_NAME.test(entry.name)) {
      throw new Error("invalid bundle entry name");
    }

    const expanded = inflateRawSync(entry.compressed);
    storage.put(entry.name, expanded);
  }
}
