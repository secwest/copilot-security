import express from "express";
import { routeOperator } from "./gateway.js";

const app = express();

app.get("/run", async (request, response) => {
  const operator = request.query.operator;
  const result = await routeOperator(operator);
  response.json({ result });
});
