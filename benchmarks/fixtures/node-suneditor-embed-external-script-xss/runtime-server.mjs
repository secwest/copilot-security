import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)));
let requestCount = 0;
const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
]);

const server = createServer(async (request, response) => {
  const url = new URL(request.url || "/", "http://127.0.0.1");
  if (url.pathname === "/payload.js") {
    requestCount += 1;
    response.writeHead(200, {
      "content-type": "text/javascript; charset=utf-8",
    });
    response.end(
      "globalThis.__suneditorInertSentinel = (globalThis.__suneditorInertSentinel || 0) + 1;",
    );
    return;
  }
  if (url.pathname === "/metrics") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ requestCount }));
    return;
  }
  const relative = decodeURIComponent(url.pathname).replace(/^\/+/, "");
  const path = resolve(root, relative || "runtime-witness.html");
  if (path !== root && !path.startsWith(`${root}${sep}`)) {
    response.writeHead(404).end();
    return;
  }
  try {
    const body = await readFile(path);
    response.writeHead(200, {
      "content-type":
        contentTypes.get(extname(path)) || "application/octet-stream",
    });
    response.end(body);
  } catch {
    response.writeHead(404).end();
  }
});

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (typeof address === "object" && address !== null) {
    process.stdout.write(`${JSON.stringify({ port: address.port })}\n`);
  }
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
