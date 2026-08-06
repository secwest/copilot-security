import express from "express";
import { routeAccountPatch } from "./gateway.js";

const app = express();
app.use(express.json());

app.patch("/account", async (request, response) => {
  const result = await routeAccountPatch(request.body.patch);
  response.json(result);
});

export { app };
