import express from "express";
import { ingestPacket } from "./gateway.js";

const app = express();

app.post("/packet", express.raw({ type: "*/*" }), (request, response) => {
  ingestPacket(request.body);
  response.sendStatus(202);
});

export { app };
