import express from "express";
import { routeSetting } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/settings", (request, response) => {
  const settings = routeSetting(request.body.path);
  const policy = {};
  response.json({ settings, administrator: policy.isAdmin === true });
});

export { app };
