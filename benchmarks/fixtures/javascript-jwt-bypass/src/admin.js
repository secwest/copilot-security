import jwt from "jsonwebtoken";

export function exportCustomers(request, response, database) {
  const token = String(request.headers.authorization ?? "").replace(
    /^Bearer\s+/i,
    "",
  );
  const claims = jwt.decode(token);
  if (claims?.admin !== true) return response.status(403).end();
  return response.json(database.exportAllCustomers());
}
