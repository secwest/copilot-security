import { unflatten } from "flat";

export function materializeSettings(entries) {
  return unflatten(entries);
}
