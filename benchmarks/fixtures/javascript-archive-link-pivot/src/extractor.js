import { posix as path } from "node:path";

export function extractArchive(destination, entries, filesystem) {
  const root = path.resolve("/", destination);

  for (const entry of entries) {
    const target = containedMemberTarget(root, entry.name);
    if (entry.type === "directory") {
      filesystem.mkdir(target);
      continue;
    }
    if (entry.type === "symlink") {
      filesystem.mkdir(path.dirname(target));
      filesystem.symlink(entry.linkName, target);
      continue;
    }
    if (entry.type === "hardlink") {
      filesystem.mkdir(path.dirname(target));
      filesystem.hardlink(path.resolve(root, entry.linkName), target);
      continue;
    }
    if (entry.type !== "file") throw new Error("unsupported archive entry");

    filesystem.mkdir(path.dirname(target));
    filesystem.writeFile(target, entry.data);
  }
}

function containedMemberTarget(root, memberName) {
  const target = path.resolve(root, memberName);
  if (target !== root && !target.startsWith(`${root}/`)) {
    throw new Error("archive member escapes extraction root");
  }
  return target;
}
