import express from "express";
import { routeTemplate } from "./gateway.js";

const app = express();
app.use(express.json());

app.get("/preview", async (request, response) => {
  response.send(await routeTemplate(request.query.template));
});

export { app };
