import { Address4 } from "ip-address";

export async function fetchProfile(rawUrl) {
  const host = new URL(rawUrl).hostname;
  const address = new Address4(host);
  if (address.isPrivate()) throw new Error("private address");
  return fetch(rawUrl);
}
