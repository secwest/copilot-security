import express from "express";
import { routeArchive } from "./gateway.js";

const app = express();

app.post("/plugins", async (request, response) => {
  const result = await routeArchive(request.file.path);
  response.status(200).json(result);
});

export { app };
