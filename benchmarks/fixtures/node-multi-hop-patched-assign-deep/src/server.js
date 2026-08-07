import express from "express";
import { routeOptions } from "./gateway.js";

const app = express();
app.use(express.json());
app.post("/options", (request, response) => {
  try {
    routeOptions(request.body);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
  }
  const policy = {};
  response.json({ administrator: policy.isAdministrator === true });
});

export { app };
