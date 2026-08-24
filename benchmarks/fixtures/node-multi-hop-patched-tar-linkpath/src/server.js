import { receiveTar } from "./gateway.js";

export function importRoute(request) {
  const user = request.user;
  authorizeImport(user);
  auditImport(user);
  return receiveTar(request.file.path);
}
