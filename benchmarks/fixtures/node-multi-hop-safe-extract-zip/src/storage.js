import extract from "extract-zip";

export async function installArchive(path) {
  await extract(path, {
    dir: "/srv/plugins",
    onEntry: (entry) => {
      const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
      if (mode === 0o120000) throw new Error("links rejected");
    },
  });
  return { config: "/srv/plugins/current/config.json" };
}
