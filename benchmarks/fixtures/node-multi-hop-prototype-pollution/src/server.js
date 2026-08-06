import express from "express";
import { routePreference } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/preferences", (request, response) => {
  const updated = routePreference(request.body);
  response.json({ updated });
});

export { app };
