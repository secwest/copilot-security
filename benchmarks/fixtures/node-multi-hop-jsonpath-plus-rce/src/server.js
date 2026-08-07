import express from "express";
import { routeSelection } from "./gateway.js";

const app = express();
app.use(express.json());

app.get("/records", (request, response) => {
  response.json(routeSelection(request.query.path));
});

export { app };
