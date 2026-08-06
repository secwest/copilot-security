import express from "express";
import { routeAccountLookup } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/account", async (request, response) => {
  const account = await routeAccountLookup(request.body.username);
  response.json(account);
});

export { app };
