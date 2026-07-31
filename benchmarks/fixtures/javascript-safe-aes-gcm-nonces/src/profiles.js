import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from "node:crypto";

const KEY_ID = "profiles-v1";
const GCM_SALT_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const PER_ENVELOPE_NONCE = Buffer.alloc(GCM_NONCE_BYTES, 0);

export function sealProfile(profileId, plaintext, masterKey, blobStore) {
  validateInputs(profileId, plaintext, masterKey);
  const salt = randomBytes(GCM_SALT_BYTES);
  const dataKey = deriveDataKey(masterKey, salt, profileId);
  const cipher = createCipheriv("aes-256-gcm", dataKey, PER_ENVELOPE_NONCE);
  cipher.setAAD(authenticatedMetadata(profileId));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelope = {
    keyId: KEY_ID,
    salt,
    nonce: Buffer.from(PER_ENVELOPE_NONCE),
    ciphertext,
    tag: cipher.getAuthTag(),
  };
  blobStore.publish(profileId, envelope);
  return envelope;
}

export function openProfile(profileId, envelope, masterKey) {
  validateInputs(profileId, envelope.ciphertext, masterKey);
  if (
    envelope.keyId !== KEY_ID ||
    !Buffer.isBuffer(envelope.salt) ||
    envelope.salt.byteLength !== GCM_SALT_BYTES ||
    !Buffer.isBuffer(envelope.nonce) ||
    envelope.nonce.byteLength !== GCM_NONCE_BYTES ||
    !Buffer.isBuffer(envelope.tag) ||
    envelope.tag.byteLength !== 16
  ) {
    throw new Error("invalid encrypted profile envelope");
  }
  const dataKey = deriveDataKey(masterKey, envelope.salt, profileId);
  const decipher = createDecipheriv("aes-256-gcm", dataKey, envelope.nonce);
  decipher.setAAD(authenticatedMetadata(profileId));
  decipher.setAuthTag(envelope.tag);
  try {
    return Buffer.concat([
      decipher.update(envelope.ciphertext),
      decipher.final(),
    ]);
  } catch (error) {
    throw new Error("encrypted profile authentication failed", {
      cause: error,
    });
  }
}

function deriveDataKey(masterKey, salt, profileId) {
  return Buffer.from(
    hkdfSync(
      "sha256",
      masterKey,
      salt,
      Buffer.from(`${KEY_ID}\0${profileId}`, "utf8"),
      32,
    ),
  );
}

function authenticatedMetadata(profileId) {
  return Buffer.from(JSON.stringify({ keyId: KEY_ID, profileId }), "utf8");
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
