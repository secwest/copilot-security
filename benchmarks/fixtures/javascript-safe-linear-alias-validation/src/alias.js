const MAX_ALIAS_LENGTH = 64;

export function registerAlias(request, registry) {
  const alias = request.body.alias;
  if (!isValidAlias(alias)) {
    return response(400, { error: "invalid_alias" });
  }

  registry.reserve(alias);
  return response(201, { alias });
}

function isValidAlias(alias) {
  if (
    typeof alias !== "string" ||
    alias.length === 0 ||
    alias.length > MAX_ALIAS_LENGTH
  ) {
    return false;
  }
  for (let index = 0; index < alias.length; index += 1) {
    if (alias.charCodeAt(index) !== 0x61) return false;
  }
  return true;
}

function response(status, body) {
  return { status, body };
}
