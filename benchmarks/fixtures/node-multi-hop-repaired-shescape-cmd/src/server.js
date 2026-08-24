import express from "express";
import { routeCommand } from "./gateway.js";

const app = express();

app.get("/diagnostics", (request, response) => {
  const value = request.query.value;
  response.type("text/plain").send(routeCommand(value));
});
