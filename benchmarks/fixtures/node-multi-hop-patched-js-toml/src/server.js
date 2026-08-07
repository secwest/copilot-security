import express from "express";
import { routeDocument } from "./gateway.js";

const app = express();
app.use(express.text({ type: "application/toml" }));

app.post("/options", (request, response) => {
  routeDocument(request.body);
  const policy = {};
  response.json({ administrator: policy.isAdmin === true });
});

export { app };
