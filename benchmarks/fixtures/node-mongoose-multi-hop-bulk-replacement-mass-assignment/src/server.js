import express from "express";
import { routeAccountReplacement } from "./gateway.js";

const app = express();
app.use(express.json());

app.put("/account", async (request, response) => {
  const result = await routeAccountReplacement(request.body.document);
  response.json(result);
});

export { app };
