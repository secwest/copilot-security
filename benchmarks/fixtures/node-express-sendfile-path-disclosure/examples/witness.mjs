import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";

const moduleUrl = process.env.COPILOT_SECURITY_EXPRESS_MODULE_URL;
if (!moduleUrl) throw new Error("missing Express module URL");
const imported = await import(moduleUrl);
const express = imported.default ?? imported;

async function dispatch(app, url) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    const socket = new Duplex({
      read() {},
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      },
    });
    const request = new IncomingMessage(socket);
    request.method = "GET";
    request.url = url;
    request.headers = { host: "benchmark.invalid" };
    request.push(null);
    const response = new ServerResponse(request);
    response.assignSocket(socket);
    const timer = setTimeout(
      () => reject(new Error("in-memory Express response timed out")),
      5_000,
    );
    response.once("error", reject);
    response.once("finish", () => {
      clearTimeout(timer);
      resolve({
        body: Buffer.concat(chunks).toString("utf8"),
        status: response.statusCode,
      });
    });
    app.handle(request, response, (error) => {
      if (response.writableEnded) return;
      response.statusCode = Number(error?.statusCode ?? error?.status ?? 404);
      response.end();
    });
  });
}

const disposableRoot = await mkdtemp(
  join(tmpdir(), "express-sendfile-witness-"),
);
try {
  const downloadRoot = join(disposableRoot, "downloads");
  const outsidePath = join(disposableRoot, "outside-marker.txt");
  const insidePath = join(downloadRoot, "inside-marker.txt");
  const outsideMarker = "inert-outside-marker-63f14c";
  const insideMarker = "inert-inside-marker-8a20d1";
  await mkdir(downloadRoot);
  await writeFile(outsidePath, outsideMarker);
  await writeFile(insidePath, insideMarker);

  const app = express();
  app.get("/download", (request, response) =>
    response.sendFile(request.query.path),
  );

  const attack = await dispatch(
    app,
    `/download?path=${encodeURIComponent(outsidePath)}`,
  );
  const allowed = await dispatch(
    app,
    `/download?path=${encodeURIComponent(insidePath)}`,
  );
  process.stdout.write(
    `${JSON.stringify({
      allowed_file_served: allowed.body.includes(insideMarker),
      attack_disclosed_outside_file: attack.body.includes(outsideMarker),
      attack_status: attack.status,
      control: false,
      listener_started: false,
      network_request_sent: false,
    })}\n`,
  );
} finally {
  await rm(disposableRoot, { recursive: true, force: true });
}
