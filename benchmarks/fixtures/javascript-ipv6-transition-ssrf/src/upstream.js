function isPrivateIpv4(host) {
  return /^(?:10\.|127\.|169\.254\.|192\.168\.)/.test(host);
}

export async function fetchPreview(rawUrl) {
  const host = new URL(rawUrl).hostname;
  if (isPrivateIpv4(host)) throw new Error("private destination");
  const response = await fetch(rawUrl);
  return response.text();
}
