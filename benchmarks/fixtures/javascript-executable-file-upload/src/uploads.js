import { writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function uploadPlugin(request, response, applicationRoot) {
  const destination = join(
    applicationRoot,
    "plugins",
    request.file.originalname,
  );
  await writeFile(destination, request.file.buffer);
  return response.status(201).json({ name: request.file.originalname });
}
