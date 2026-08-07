import express from "express";
import { routeStyle } from "./gateway.js";

const app = express();
app.use(express.text({ type: "text/css" }));

app.post("/styles", async (request, response) => {
  const result = await routeStyle(request.body);
  response.status(200).json(result);
});

export { app };
