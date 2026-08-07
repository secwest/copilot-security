import express from "express";
import { routeSettings } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/settings", (request, response) => {
  const settings = routeSettings(request.body);
  const policy = {};
  response.json({ settings, administrator: policy.isAdmin === true });
});

export { app };
