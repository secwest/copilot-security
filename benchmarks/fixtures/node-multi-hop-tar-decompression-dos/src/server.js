import { inspectUpload } from "./gateway.js";

export async function uploadRoute(request) {
  const user = request.user;
  authorizeUpload(user);
  auditUpload(user);
  const archivePath = request.file.path;
  return inspectUpload(archivePath);
}
