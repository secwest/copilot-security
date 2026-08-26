import { createServer } from "node:http";

const marker = "inert-traefik-docker-label-route-boundary";

createServer((request, response) => {
  const rawPath = request.url ?? "";
  const normalizedPath = new URL(rawPath, "http://backend.invalid").pathname;
  if (normalizedPath === "/admin") {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end(marker);
    return;
  }
  response.writeHead(404, { "content-type": "text/plain" });
  response.end("not found");
}).listen(3000, "0.0.0.0");
