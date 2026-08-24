import express from "express";
import { routeArchive } from "./gateway.js";

const app = express();

app.post(
  "/imports",
  express.raw({ type: "application/octet-stream" }),
  async (request, response) => {
    const archive = request.body;
    await routeArchive(archive);
    response.status(204).end();
  },
);
