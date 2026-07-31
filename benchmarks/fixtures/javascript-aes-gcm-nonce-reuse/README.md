# Vulnerable AES-GCM nonce-reuse fixture

The profile backup service publishes authenticated ciphertext envelopes while
reusing one fixed 96-bit nonce with the same AES-256-GCM key. An attacker who
requests a known plaintext of the victim ciphertext's length can XOR the two
ciphertexts with that plaintext and recover the victim profile. Valid
authentication tags and profile-bound additional authenticated data do not
restore confidentiality after the key/nonce pair is reused.
