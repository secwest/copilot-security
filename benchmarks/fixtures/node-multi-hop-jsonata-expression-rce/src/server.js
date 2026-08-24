import express from "express";
import { routeExpression } from "./gateway.js";

const app = express();
app.use(express.json());

app.get("/records", async (request, response) => {
  response.json(await routeExpression(request.query.expression));
});

export { app };
