import { dset } from "dset";
const settings = {};
export function persistSetting(path) {
  dset(settings, path, true);
  return settings;
}
