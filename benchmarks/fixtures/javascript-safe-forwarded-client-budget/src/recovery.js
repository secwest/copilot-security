const MAX_FORWARDED_LENGTH = 512;
const MAX_FORWARDED_HOPS = 8;

function canonicalIpv4(value) {
  if (typeof value !== "string" || value.length < 7 || value.length > 15) {
    throw new Error("invalid client address");
  }
  const parts = value.split(".");
  if (
    parts.length !== 4 ||
    parts.some(
      (part) =>
        !/^(?:0|[1-9][0-9]{0,2})$/.test(part) ||
        Number(part) > 255 ||
        String(Number(part)) !== part,
    )
  ) {
    throw new Error("invalid client address");
  }
  return parts.join(".");
}

function forwardedHops(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_FORWARDED_LENGTH
  ) {
    throw new Error("invalid forwarding chain");
  }
  const hops = value.split(",");
  if (hops.length === 0 || hops.length > MAX_FORWARDED_HOPS) {
    throw new Error("invalid forwarding chain");
  }
  return hops.map((hop) => canonicalIpv4(hop.trim()));
}

export function trustedClientAddress(request, trustedProxies) {
  const peerAddress = canonicalIpv4(request.peerAddress);
  if (!trustedProxies.has(peerAddress)) {
    return peerAddress;
  }

  const chain = [
    ...forwardedHops(request.headers?.["x-forwarded-for"]),
    peerAddress,
  ];
  let index = chain.length - 1;
  while (index > 0 && trustedProxies.has(chain[index])) {
    index -= 1;
  }
  return chain[index];
}

export class RecoveryGateway {
  #attemptsByAccount = new Map();
  #attemptsByClient = new Map();
  #passwords = new Map();

  constructor({
    recoveryCodes,
    trustedProxies,
    maxAttemptsPerAccount = 3,
    maxAttemptsPerClient = 3,
  }) {
    this.recoveryCodes = new Map(recoveryCodes);
    this.trustedProxies = new Set(
      [...trustedProxies].map((address) => canonicalIpv4(address)),
    );
    this.maxAttemptsPerAccount = maxAttemptsPerAccount;
    this.maxAttemptsPerClient = maxAttemptsPerClient;
  }

  recover(request) {
    let clientAddress;
    try {
      clientAddress = trustedClientAddress(request, this.trustedProxies);
    } catch {
      return { status: 400, body: { error: "invalid_forwarding_chain" } };
    }

    const clientAttempts = (this.#attemptsByClient.get(clientAddress) ?? 0) + 1;
    const accountAttempts =
      (this.#attemptsByAccount.get(request.accountId) ?? 0) + 1;
    if (
      clientAttempts > this.maxAttemptsPerClient ||
      accountAttempts > this.maxAttemptsPerAccount
    ) {
      return { status: 429, body: { error: "too_many_attempts" } };
    }
    this.#attemptsByClient.set(clientAddress, clientAttempts);
    this.#attemptsByAccount.set(request.accountId, accountAttempts);

    if (this.recoveryCodes.get(request.accountId) !== request.recoveryCode) {
      return { status: 401, body: { error: "invalid_recovery_code" } };
    }
    this.#passwords.set(request.accountId, request.newPassword);
    return { status: 200, body: { recovered: true } };
  }

  passwordFor(accountId) {
    return this.#passwords.get(accountId);
  }

  attemptsForAccount(accountId) {
    return this.#attemptsByAccount.get(accountId) ?? 0;
  }

  attemptsForClient(clientAddress) {
    return this.#attemptsByClient.get(clientAddress) ?? 0;
  }
}
