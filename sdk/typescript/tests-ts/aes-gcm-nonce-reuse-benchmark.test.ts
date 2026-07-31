import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";

type Envelope = {
  keyId: string;
  salt?: Buffer;
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
};

interface Fixture {
  sealProfile(
    profileId: string,
    plaintext: Buffer,
    key: Buffer,
    blobStore: PublicBlobStore,
  ): Envelope;
  openProfile(profileId: string, envelope: Envelope, key: Buffer): Buffer;
}

class PublicBlobStore {
  readonly #profiles = new Map<string, Envelope>();

  publish(profileId: string, envelope: Envelope): void {
    this.#profiles.set(profileId, cloneEnvelope(envelope));
  }

  get(profileId: string): Envelope {
    const envelope = this.#profiles.get(profileId);
    if (envelope === undefined) throw new Error("missing profile envelope");
    return cloneEnvelope(envelope);
  }
}

describe("AES-GCM nonce-reuse benchmark", () => {
  test("a repeated key and nonce reveal a victim profile from known plaintext", async () => {
    const fixture = await loadFixture("javascript-aes-gcm-nonce-reuse");
    const store = new PublicBlobStore();
    const key = Buffer.alloc(32, 0x5e);
    const secret = Buffer.from("victim recovery code: secwest-2026-rotate-now");
    const known = Buffer.alloc(secret.byteLength, 0x41);

    fixture.sealProfile("victim", secret, key, store);
    fixture.sealProfile("attacker", known, key, store);
    const victim = store.get("victim");
    const attacker = store.get("attacker");
    const recovered = xorBuffers(
      xorBuffers(victim.ciphertext, attacker.ciphertext),
      known,
    );

    expect(victim.nonce).toEqual(attacker.nonce);
    expect(victim.tag.byteLength).toBe(16);
    expect(attacker.tag.byteLength).toBe(16);
    expect(fixture.openProfile("victim", victim, key)).toEqual(secret);
    expect(fixture.openProfile("attacker", attacker, key)).toEqual(known);
    expect(recovered).toEqual(secret);
  });

  test("per-envelope data keys defeat recovery even when visible nonces repeat", async () => {
    const fixture = await loadFixture("javascript-safe-aes-gcm-nonces");
    const store = new PublicBlobStore();
    const key = Buffer.alloc(32, 0x5e);
    const secret = Buffer.from("victim recovery code: secwest-2026-rotate-now");
    const known = Buffer.alloc(secret.byteLength, 0x41);

    fixture.sealProfile("victim", secret, key, store);
    fixture.sealProfile("attacker", known, key, store);
    const victim = store.get("victim");
    const attacker = store.get("attacker");
    const invalidRecovery = xorBuffers(
      xorBuffers(victim.ciphertext, attacker.ciphertext),
      known,
    );

    expect(victim.nonce).toEqual(attacker.nonce);
    expect(victim.salt).not.toEqual(attacker.salt);
    expect(invalidRecovery).not.toEqual(secret);
    expect(fixture.openProfile("victim", victim, key)).toEqual(secret);
    expect(fixture.openProfile("attacker", attacker, key)).toEqual(known);
  });

  test("the safe profile identifier is authenticated with the envelope", async () => {
    const fixture = await loadFixture("javascript-safe-aes-gcm-nonces");
    const store = new PublicBlobStore();
    const key = Buffer.alloc(32, 0x5e);
    const secret = Buffer.from("profile-bound plaintext");

    fixture.sealProfile("victim", secret, key, store);
    const victim = store.get("victim");

    expect(() => fixture.openProfile("attacker", victim, key)).toThrow(
      "encrypted profile authentication failed",
    );
  });

  test("the safe decoder fails closed on ciphertext modification", async () => {
    const fixture = await loadFixture("javascript-safe-aes-gcm-nonces");
    const store = new PublicBlobStore();
    const key = Buffer.alloc(32, 0x5e);

    fixture.sealProfile(
      "victim",
      Buffer.from("authenticated plaintext"),
      key,
      store,
    );
    const victim = store.get("victim");
    victim.ciphertext[0] = victim.ciphertext[0]! ^ 0x01;

    expect(() => fixture.openProfile("victim", victim, key)).toThrow(
      "encrypted profile authentication failed",
    );
  });
});

function xorBuffers(left: Buffer, right: Buffer): Buffer {
  if (left.byteLength !== right.byteLength) {
    throw new Error("XOR inputs must have equal length");
  }
  const output = Buffer.allocUnsafe(left.byteLength);
  for (let index = 0; index < output.byteLength; index += 1) {
    output[index] = left[index]! ^ right[index]!;
  }
  return output;
}

function cloneEnvelope(envelope: Envelope): Envelope {
  return {
    keyId: envelope.keyId,
    ...(envelope.salt === undefined
      ? {}
      : { salt: Buffer.from(envelope.salt) }),
    nonce: Buffer.from(envelope.nonce),
    ciphertext: Buffer.from(envelope.ciphertext),
    tag: Buffer.from(envelope.tag),
  };
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
    "profiles.js",
  );
  return (await import(pathToFileURL(source).href)) as Fixture;
}
