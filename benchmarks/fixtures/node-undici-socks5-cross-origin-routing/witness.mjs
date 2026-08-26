import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import { createRequire } from "node:module";
import { connect, createServer as createTcpServer } from "node:net";

const { Socks5ProxyAgent, request } = createRequire(
  `${process.cwd()}/package.json`,
)("undici");

const marker = "Bearer inert-cross-origin-witness";
const seen = { A: [], B: [] };

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}

function target(label) {
  return createHttpServer((req, res) => {
    seen[label].push({
      path: req.url,
      authorization: req.headers.authorization,
    });
    res.setHeader("connection", "keep-alive");
    res.end(label);
  });
}

function socksProxy() {
  return createTcpServer((client) => {
    let phase = "greeting";
    let buffered = Buffer.alloc(0);
    client.on("data", function negotiate(chunk) {
      buffered = Buffer.concat([buffered, chunk]);
      if (phase === "greeting") {
        if (buffered.length < 2 + buffered[1]) return;
        buffered = buffered.subarray(2 + buffered[1]);
        client.write(Buffer.from([5, 0]));
        phase = "connect";
      }
      if (phase !== "connect" || buffered.length < 7) return;
      const type = buffered[3];
      let host;
      let offset;
      if (type === 1) {
        if (buffered.length < 10) return;
        host = [...buffered.subarray(4, 8)].join(".");
        offset = 8;
      } else if (type === 3) {
        const length = buffered[4];
        if (buffered.length < 7 + length) return;
        host = buffered.subarray(5, 5 + length).toString("utf8");
        offset = 5 + length;
      } else {
        client.destroy(
          new Error("Witness supports only IPv4 and domain SOCKS targets."),
        );
        return;
      }
      const port = buffered.readUInt16BE(offset);
      const remainder = buffered.subarray(offset + 2);
      client.removeListener("data", negotiate);
      const upstream = connect({ host, port }, () => {
        client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
        if (remainder.length > 0) upstream.write(remainder);
        client.pipe(upstream).pipe(client);
      });
      upstream.on("error", (error) => client.destroy(error));
      phase = "tunnel";
    });
  });
}

const first = target("A");
const second = target("B");
const proxy = socksProxy();
const [firstPort, secondPort, proxyPort] = await Promise.all([
  listen(first),
  listen(second),
  listen(proxy),
]);
const agent = new Socks5ProxyAgent(`socks5://127.0.0.1:${proxyPort}`);
try {
  const initial = await request(`http://127.0.0.1:${firstPort}/first`, {
    dispatcher: agent,
  });
  assert.equal(await initial.body.text(), "A");
  const credentialed = await request(`http://127.0.0.1:${secondPort}/second`, {
    dispatcher: agent,
    headers: { authorization: marker },
  });
  const body = await credentialed.body.text();
  const affected = seen.A.some(
    (entry) => entry.path === "/second" && entry.authorization === marker,
  );
  const repaired = seen.B.some(
    (entry) => entry.path === "/second" && entry.authorization === marker,
  );
  assert.notEqual(affected, repaired);
  assert.equal(body, affected ? "A" : "B");
  console.log(
    JSON.stringify({
      affected,
      repaired,
      firstOriginRequests: seen.A.length,
      secondOriginRequests: seen.B.length,
    }),
  );
} finally {
  await agent.close();
  await Promise.all([close(first), close(second), close(proxy)]);
}
