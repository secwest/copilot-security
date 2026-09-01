import express from "express";
import jwt from "jsonwebtoken";

const app = express();

app.get("/admin/status", (request, response) => {
  const authorization = request.get("authorization") ?? "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";
  const claims = jwt.decode(token);
  if (claims?.role !== "admin") return response.status(403).end();
  return response.json({ systemKey: process.env.SYSTEM_STATUS_KEY });
});

export default app;
