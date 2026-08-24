import express from "express";
import { routeCode } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/execute", async (request, response) => {
  response.json(await routeCode(request.body.code));
});

export { app };
