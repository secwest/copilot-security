import jwt from "jsonwebtoken";

export function exportCustomers(request, response, database) {
  const token = String(request.headers.authorization ?? "").replace(
    /^Bearer\s+/i,
    "",
  );
  const claims = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
    algorithms: ["RS256"],
    audience: "admin-api",
    issuer: "https://identity.example",
  });
  if (claims.admin !== true) return response.status(403).end();
  return response.json(database.exportAllCustomers());
}
