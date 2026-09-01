import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import bcrypt from "bcryptjs";

const app = Fastify();
await app.register(rateLimit, { global: false });
async function authenticate(request, reply) {
  const password = request.body.password;
  const accepted = await bcrypt.compare(password, process.env.PASSWORD_HASH);
  if (!accepted) return reply.code(401).send({ error: "invalid credentials" });
  return reply.send({ ok: true });
}

app.post(
  "/login",
  { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } },
  authenticate,
);

export { app, rateLimit };
