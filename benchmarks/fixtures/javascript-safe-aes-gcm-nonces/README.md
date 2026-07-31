# Safe AES-GCM nonce fixture

Every profile backup receives a fresh 256-bit salt and a distinct
HKDF-SHA-256-derived AES-256-GCM data key. The visible 96-bit nonce may repeat,
but never under the same data key. The envelope carries the key identifier,
salt, and nonce, while the key identifier and profile identifier are bound as
additional authenticated data. Authentication-tag verification fails closed
before plaintext is returned. Known plaintext from another envelope therefore
cannot recover the victim profile, and envelope substitution between profile
identifiers is rejected.
