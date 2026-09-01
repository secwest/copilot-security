import express from "express";

const DOWNLOAD_ROOT = "/srv/copilot-security/downloads";
const app = express();

app.get("/download", (request, response) => {
  const requestedPath = request.query.path;
  return response.sendFile(requestedPath, { root: DOWNLOAD_ROOT });
});

export default app;
