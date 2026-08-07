import express from "express";
import { routeProfileUpdate } from "./gateway.js";

const app = express();
app.use(express.json());

app.post("/profile", (request, response) => {
  const profile = routeProfileUpdate(request.body.profile);
  response.status(profile.admin ? 200 : 403).json(profile);
});

export { app };
