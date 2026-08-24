import { inspectTar } from "./gateway.js";

export function inspectRoute(request) {
  const user = request.user;
  authorizeInspection(user);
  auditInspection(user);
  return inspectTar(request.file.path);
}
