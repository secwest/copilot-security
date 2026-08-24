import express from "express";
import { routeRawMessage } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/messages/raw", async (request, response) => {
  const result = await routeRawMessage(request.body);
  response.status(202).json({ messageId: result.messageId });
});

export { app };
