import { execFile } from "node:child_process";

const HOSTNAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i;

export function checkHost(request, response) {
  const host = String(request.query.host ?? "");
  if (!HOSTNAME.test(host)) return response.status(400).end();
  execFile("printf", ["%s", host], (error, stdout) =>
    response.json({ error: error?.message, stdout }),
  );
}
