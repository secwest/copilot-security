import { deflateRawSync } from "node:zlib";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";

type BundleEntry = {
  name: string;
  compressed: Buffer;
  uncompressedSize: number;
};

interface Fixture {
  importBundle(entries: BundleEntry[], storage: MemoryStorage): void;
}

class MemoryStorage {
  readonly #entries = new Map<string, Buffer>();

  put(name: string, data: Uint8Array): void {
    this.#entries.set(name, Buffer.from(data));
  }

  get(name: string): Buffer | undefined {
    return this.#entries.get(name);
  }

  has(name: string): boolean {
    return this.#entries.has(name);
  }
}

describe("decompression-bomb benchmark", () => {
  test("a tiny valid DEFLATE stream expands without an output budget", async () => {
    const fixture = await loadFixture("javascript-decompression-bomb");
    const storage = new MemoryStorage();
    const expanded = Buffer.alloc(8 * 1024 * 1024, 0x41);
    const compressed = deflateRawSync(expanded, { level: 9 });

    expect(compressed.byteLength * 500).toBeLessThan(expanded.byteLength);
    fixture.importBundle(
      [
        {
          name: "profile.data",
          compressed,
          uncompressedSize: 1024,
        },
      ],
      storage,
    );

    expect(storage.get("profile.data")?.byteLength).toBe(expanded.byteLength);
  });

  test("actual-output limits defeat a bomb that lies about its size", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const compressed = deflateRawSync(Buffer.alloc(8 * 1024 * 1024, 0x41), {
      level: 9,
    });

    expect(() =>
      fixture.importBundle(
        [
          {
            name: "profile.data",
            compressed,
            uncompressedSize: 1024,
          },
        ],
        storage,
      ),
    ).toThrow("compressed entry is invalid or exceeds decompression limits");
    expect(storage.has("profile.data")).toBe(false);
  });

  test("the expansion-ratio control rejects a bounded but abusive output", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const expanded = Buffer.alloc(1024 * 1024, 0x42);

    expect(() =>
      fixture.importBundle(
        [
          {
            name: "ratio.data",
            compressed: deflateRawSync(expanded, { level: 9 }),
            uncompressedSize: expanded.byteLength,
          },
        ],
        storage,
      ),
    ).toThrow("decompression expansion ratio exceeds limit");
    expect(storage.has("ratio.data")).toBe(false);
  });

  test("malformed compressed data fails closed before storage", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();

    expect(() =>
      fixture.importBundle(
        [
          {
            name: "broken.data",
            compressed: Buffer.from([0xff, 0x00, 0xff, 0x00]),
            uncompressedSize: 32,
          },
        ],
        storage,
      ),
    ).toThrow("compressed entry is invalid or exceeds decompression limits");
    expect(storage.has("broken.data")).toBe(false);
  });

  test("an entry-count budget rejects many zero-output members", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const empty = deflateRawSync(Buffer.alloc(0));
    const entries = Array.from({ length: 129 }, (_, index) => ({
      name: `empty-${index}.data`,
      compressed: empty,
      uncompressedSize: 0,
    }));

    expect(() => fixture.importBundle(entries, storage)).toThrow(
      "bundle entry count exceeds limit",
    );
    expect(storage.has("empty-0.data")).toBe(false);
  });

  test("bounded index iteration ignores a custom array iterator", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const expanded = Buffer.from("ordinary payload");
    const entries = [
      {
        name: "ordinary.data",
        compressed: deflateRawSync(expanded),
        uncompressedSize: expanded.byteLength,
      },
    ];
    Object.defineProperty(entries, Symbol.iterator, {
      value: function* hostileIterator() {
        throw new Error("custom iterator consumed");
      },
    });

    fixture.importBundle(entries, storage);

    expect(storage.get("ordinary.data")).toEqual(expanded);
  });

  test("the entry-count gate snapshots a mutable array length", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const expanded = Buffer.from("ordinary payload");
    const entry = {
      name: "ordinary.data",
      compressed: deflateRawSync(expanded),
      uncompressedSize: expanded.byteLength,
    };
    let lengthReads = 0;
    const entries = new Proxy([entry], {
      get(target, property, receiver) {
        if (property === "length") {
          lengthReads += 1;
          return lengthReads === 1 ? 1 : 129;
        }
        return Reflect.get(target, property, receiver);
      },
    });

    fixture.importBundle(entries, storage);

    expect(lengthReads).toBe(1);
    expect(storage.get("ordinary.data")).toEqual(expanded);
  });

  test("entry fields are snapshotted before validation and storage", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const expanded = Buffer.from("ordinary payload");
    let nameReads = 0;
    const entry = {
      get name() {
        nameReads += 1;
        return nameReads === 1 ? "ordinary.data" : "../outside";
      },
      compressed: deflateRawSync(expanded),
      uncompressedSize: expanded.byteLength,
    };

    fixture.importBundle([entry], storage);

    expect(nameReads).toBe(1);
    expect(storage.get("ordinary.data")).toEqual(expanded);
    expect(storage.has("../outside")).toBe(false);
  });

  test("one cumulative budget stops many individually acceptable entries", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const entries = [1, 2, 3].map((seed) => {
      const expanded = deterministicBytes(1536 * 1024, seed);
      return {
        name: `part-${seed}.data`,
        compressed: deflateRawSync(expanded, { level: 1 }),
        uncompressedSize: expanded.byteLength,
      };
    });

    expect(() => fixture.importBundle(entries, storage)).toThrow(
      "bundle exceeds cumulative decompression limit",
    );
    expect(storage.has("part-1.data")).toBe(false);
    expect(storage.has("part-2.data")).toBe(false);
    expect(storage.has("part-3.data")).toBe(false);
  });

  test("one cumulative compressed-input budget bounds decoder work", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const stream = deflateRawSync(Buffer.from("x"));
    const padded = Buffer.concat([
      stream,
      Buffer.alloc(2 * 1024 * 1024 - stream.byteLength),
    ]);
    const entries = [1, 2, 3].map((index) => ({
      name: `padded-${index}.data`,
      compressed: padded,
      uncompressedSize: 1,
    }));

    expect(() => fixture.importBundle(entries, storage)).toThrow(
      "bundle exceeds cumulative compressed-input limit",
    );
    expect(storage.has("padded-1.data")).toBe(false);
  });

  test("duplicate names fail before any staged entry is stored", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const expanded = Buffer.from("ordinary payload");
    const entry = {
      name: "duplicate.data",
      compressed: deflateRawSync(expanded),
      uncompressedSize: expanded.byteLength,
    };

    expect(() => fixture.importBundle([entry, entry], storage)).toThrow(
      "duplicate bundle entry name",
    );
    expect(storage.has("duplicate.data")).toBe(false);
  });

  test("bounded ordinary compressed data remains usable", async () => {
    const fixture = await loadFixture("javascript-safe-decompression-limits");
    const storage = new MemoryStorage();
    const expanded = deterministicBytes(256 * 1024, 0x5ec0);

    fixture.importBundle(
      [
        {
          name: "ordinary.data",
          compressed: deflateRawSync(expanded),
          uncompressedSize: expanded.byteLength,
        },
      ],
      storage,
    );

    expect(storage.get("ordinary.data")).toEqual(expanded);
  });
});

function deterministicBytes(length: number, seed: number): Buffer {
  const bytes = Buffer.allocUnsafe(length);
  let state = seed >>> 0;
  for (let index = 0; index < bytes.length; index += 1) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    bytes[index] = state >>> 24;
  }
  return bytes;
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
    "importer.js",
  );
  return (await import(pathToFileURL(source).href)) as Fixture;
}
