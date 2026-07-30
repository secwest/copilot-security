import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

const MAX_PROFILE_BYTES = 4096;
const THEME = /^(?:dark|light)$/u;

export async function storeProfile(request, response, applicationRoot) {
  if (
    request.file.mimetype !== "application/json" ||
    request.file.buffer.length > MAX_PROFILE_BYTES
  ) {
    return response.status(415).end();
  }

  let profile;
  try {
    profile = JSON.parse(request.file.buffer.toString("utf8"));
  } catch {
    return response.status(400).end();
  }
  if (
    typeof profile !== "object" ||
    profile === null ||
    Array.isArray(profile) ||
    Object.keys(profile).some((key) => key !== "theme") ||
    typeof profile.theme !== "string" ||
    !THEME.test(profile.theme)
  ) {
    return response.status(400).end();
  }

  const name = `${randomUUID()}.json`;
  const profileDirectory = join(applicationRoot, "data", "profiles");
  const canonical = `${JSON.stringify({ theme: profile.theme })}\n`;
  await writeFile(join(profileDirectory, name), canonical, {
    encoding: "utf8",
    flag: "wx",
  });
  return response.status(201).json({ name });
}
