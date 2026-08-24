import { extractArchive } from "./storage.js";

export async function prepareArchive(archive) {
  return extractArchive(archive);
}
