import express from "express";
import { routeAccountMaintenance } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/account-maintenance", async (request, response) => {
  const result = await routeAccountMaintenance(request.body.pipeline);
  response.json(result);
});

export { app };
