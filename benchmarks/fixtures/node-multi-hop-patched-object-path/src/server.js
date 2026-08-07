import express from "express";
import { routeRemoval } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/settings/remove", (request, response) => {
  routeRemoval(request.body.path);
  response.json({ removed: true });
});

export { app };
