const SETTINGS = new Map();

export function storePreference(patch) {
  const namespace = SETTINGS.get(patch.namespace) ?? new Map();
  namespace.set(patch.key, patch.value);
  SETTINGS.set(patch.namespace, namespace);
  return namespace.get(patch.key);
}
