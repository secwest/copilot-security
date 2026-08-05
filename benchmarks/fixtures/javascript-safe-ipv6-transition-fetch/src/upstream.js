function embeddedIpv4(firstWord, secondWord) {
  const value =
    (Number.parseInt(firstWord, 16) << 16) | Number.parseInt(secondWord, 16);
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

function canonicalizeIpv6TransitionAddress(host) {
  const normalized = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized.startsWith("::ffff:")) return normalized.slice(7);
  if (normalized.startsWith("64:ff9b::")) {
    const words = normalized.slice(9).split(":");
    return embeddedIpv4(words.at(-2), words.at(-1));
  }
  if (normalized.startsWith("2002:")) {
    const words = normalized.split(":");
    return embeddedIpv4(words[1], words[2]);
  }
  return normalized;
}

function isPrivateIpv4(host) {
  return /^(?:10\.|127\.|169\.254\.|192\.168\.)/.test(host);
}

export async function fetchPreview(rawUrl) {
  const host = new URL(rawUrl).hostname;
  const canonicalHost = canonicalizeIpv6TransitionAddress(host);
  if (isPrivateIpv4(canonicalHost)) throw new Error("private destination");
  const response = await fetch(rawUrl);
  return response.text();
}
