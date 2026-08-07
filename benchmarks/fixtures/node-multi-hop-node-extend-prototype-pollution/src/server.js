import express from "express";
import { routeOptions } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/options", (request, response) => {
  routeOptions(request.body);
  const policy = {};
  response.json({ administrator: policy.isAdministrator === true });
});

export { app };
