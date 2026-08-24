import express from "express";
import { routePattern } from "./gateway.js";

const app = express();

app.get("/expand", (request, response) => {
  const matches = routePattern(request.query.pattern);
  response.json({ count: matches.length });
});

export { app };
