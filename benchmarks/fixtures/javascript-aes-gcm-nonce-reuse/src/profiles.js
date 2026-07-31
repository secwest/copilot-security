import { createCipheriv, createDecipheriv } from "node:crypto";

const KEY_ID = "profiles-v1";
const REUSED_NONCE = Buffer.alloc(12, 0);

export function sealProfile(profileId, plaintext, key, blobStore) {
  validateInputs(profileId, plaintext, key);
  const cipher = createCipheriv("aes-256-gcm", key, REUSED_NONCE);
  cipher.setAAD(Buffer.from(profileId, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelope = {
    keyId: KEY_ID,
    nonce: Buffer.from(REUSED_NONCE),
    ciphertext,
    tag: cipher.getAuthTag(),
  };
  blobStore.publish(profileId, envelope);
  return envelope;
}

export function openProfile(profileId, envelope, key) {
  validateInputs(profileId, envelope.ciphertext, key);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(envelope.nonce),
  );
  decipher.setAAD(Buffer.from(profileId, "utf8"));
  decipher.setAuthTag(Buffer.from(envelope.tag));
  return Buffer.concat([
    decipher.update(envelope.ciphertext),
    decipher.final(),
  ]);
}

function validateInputs(profileId, plaintext, key) {
  if (typeof profileId !== "string" || profileId.length === 0) {
    throw new Error("invalid profile ID");
  }
  if (!Buffer.isBuffer(plaintext)) {
    throw new Error("profile data must be a Buffer");
  }
  if (!Buffer.isBuffer(key) || key.byteLength !== 32) {
    throw new Error("AES-256-GCM requires a 32-byte key");
  }
}
