const ALIAS_PATTERN = /^(a+)+$/;

export function registerAlias(request, registry) {
  const alias = request.body.alias;
  if (typeof alias !== "string" || !ALIAS_PATTERN.test(alias)) {
    return response(400, { error: "invalid_alias" });
  }

  registry.reserve(alias);
  return response(201, { alias });
}

function response(status, body) {
  return { status, body };
}
