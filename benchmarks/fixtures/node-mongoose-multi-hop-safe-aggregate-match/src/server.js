import express from "express";
import { routeAccountReport } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/account-report", async (request, response) => {
  const result = await routeAccountReport(request.body.criteria);
  response.json(result);
});

export { app };
