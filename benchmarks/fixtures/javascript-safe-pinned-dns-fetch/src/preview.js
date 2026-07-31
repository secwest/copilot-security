import { allAddressesPublic } from "./network-policy.js";

export async function preview(request, resolver, httpClient) {
  const rawUrl = String(request.query.url ?? "");
  let target;
  try {
    target = new URL(rawUrl);
  } catch {
    return response(400, { error: "invalid_url" });
  }

  if (
    target.protocol !== "https:" ||
    target.username !== "" ||
    target.password !== "" ||
    (target.port !== "" && target.port !== "443")
  ) {
    return response(400, { error: "unsupported_destination" });
  }

  const validatedAddresses = await resolver.resolveAll(target.hostname);
  if (!allAddressesPublic(validatedAddresses)) {
    return response(403, { error: "destination_not_public" });
  }

  const upstream = await httpClient.getPinned(target, {
    connectAddress: validatedAddresses[0],
    redirect: "error",
  });
  return response(200, { preview: upstream.body });
}

function response(status, body) {
  return { status, body };
}
