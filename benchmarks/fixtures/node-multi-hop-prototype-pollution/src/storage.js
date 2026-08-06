const SETTINGS = {};

export function storePreference(patch) {
  SETTINGS[patch.namespace][patch.key] = patch.value;
  return patch.key;
}
