import express from "express";

const app = express();

app.get("/download", (request, response) => {
  const requestedPath = request.query.path;
  return response.sendFile(requestedPath);
});

export default app;
