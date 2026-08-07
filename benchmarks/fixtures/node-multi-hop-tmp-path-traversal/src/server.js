import express from "express";
import { routeExport } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/exports", (request, response) => {
  const result = routeExport(request.query.prefix, request.body.contents);
  response.status(201).json({ path: result.name });
});

export { app };
