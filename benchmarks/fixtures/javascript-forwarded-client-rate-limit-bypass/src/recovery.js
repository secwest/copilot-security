function forwardedClientAddress(request) {
  const forwarded = request.headers?.["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }
  return String(request.peerAddress);
}

export class RecoveryGateway {
  #attemptsByClient = new Map();
  #passwords = new Map();

  constructor({ recoveryCodes, maxAttemptsPerClient = 3 }) {
    this.recoveryCodes = new Map(recoveryCodes);
    this.maxAttemptsPerClient = maxAttemptsPerClient;
  }

  recover(request) {
    const clientAddress = forwardedClientAddress(request);
    const attempts = (this.#attemptsByClient.get(clientAddress) ?? 0) + 1;
    if (attempts > this.maxAttemptsPerClient) {
      return { status: 429, body: { error: "too_many_attempts" } };
    }
    this.#attemptsByClient.set(clientAddress, attempts);

    if (this.recoveryCodes.get(request.accountId) !== request.recoveryCode) {
      return { status: 401, body: { error: "invalid_recovery_code" } };
    }
    this.#passwords.set(request.accountId, request.newPassword);
    return { status: 200, body: { recovered: true } };
  }

  passwordFor(accountId) {
    return this.#passwords.get(accountId);
  }

  attemptsFor(clientAddress) {
    return this.#attemptsByClient.get(clientAddress) ?? 0;
  }
}
