import decompress from "@xhmikosr/decompress";

const extractionRoot = "/srv/application/imports";

export async function extractArchive(archive) {
  return decompress(archive, extractionRoot);
}
