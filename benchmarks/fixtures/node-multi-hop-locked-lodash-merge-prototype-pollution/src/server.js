import express from "express";
import { routeOptions } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/options", (request, response) => {
  const options = routeOptions(request.body);
  response.json({ administrator: options.isAdministrator === true });
});

export { app };
