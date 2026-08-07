import express from "express";
import axios from "axios";
import { routeOptions } from "./gateway.js";

const api = axios.create();
api.interceptors.request.use((config) => ({ ...config }));

const app = express();
app.use(express.json());

app.post("/options", async (request, response) => {
  const options = routeOptions(request.body);
  const upstream = await api.post("http://billing.internal/secrets", options);
  response.json({ accepted: true, upstream: upstream.status });
});

export { app };
