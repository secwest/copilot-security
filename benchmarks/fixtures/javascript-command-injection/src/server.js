import { exec } from "node:child_process";

export function checkHost(request, response) {
  const host = String(request.query.host ?? "");
  exec(`ping -n 1 ${host}`, (error, stdout) =>
    response.json({ error: error?.message, stdout }),
  );
}
