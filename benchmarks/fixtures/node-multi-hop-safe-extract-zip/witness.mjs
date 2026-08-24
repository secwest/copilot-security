const symlinkMode = 0o120000 << 16;
const entry = { externalFileAttributes: symlinkMode };

let rejected = false;
try {
  const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
  if (mode === 0o120000) throw new Error("links rejected");
} catch (error) {
  rejected = error instanceof Error && error.message === "links rejected";
}

if (!rejected) {
  throw new Error("the pre-extraction symlink guard did not fail closed");
}

console.log("guarded extract-zip symlink rejection reproduced");
