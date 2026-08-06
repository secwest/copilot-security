import express from "express";
import { routeAccountView } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/account-view", async (request, response) => {
  const result = await routeAccountView(request.body.stages);
  response.json(result);
});

export { app };
