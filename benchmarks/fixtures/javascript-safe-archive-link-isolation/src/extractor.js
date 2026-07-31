import { posix as path } from "node:path";

export function extractArchive(destination, entries, filesystem) {
  const root = path.resolve("/", destination);

  for (const entry of entries) {
    if (entry.type === "symlink" || entry.type === "hardlink") {
      throw new Error("archive links are not allowed");
    }

    const target = containedMemberTarget(root, entry.name);
    if (entry.type === "directory") {
      filesystem.mkdirNoFollow(root, target);
      continue;
    }
    if (entry.type !== "file") throw new Error("unsupported archive entry");

    filesystem.mkdirNoFollow(root, path.dirname(target));
    filesystem.writeFileNoFollow(root, target, entry.data);
  }
}

function containedMemberTarget(root, memberName) {
  const target = path.resolve(root, memberName);
  if (target !== root && !target.startsWith(`${root}/`)) {
    throw new Error("archive member escapes extraction root");
  }
  return target;
}
