import { lstat } from "node:fs/promises";
import { join } from "node:path";

export async function rejectGitControlPath(root, label) {
  const metadata = await lstat(join(root, ".git")).catch((error) => {
    if (error?.code === "ENOENT") return null;
    throw error;
  });
  if (metadata !== null) {
    throw new Error(
      `${label} must not contain a pre-existing .git control path.`,
    );
  }
}
