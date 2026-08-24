import Fastify from "fastify";
import fastifyStatic from "@fastify/static";

const app = Fastify();
app.all("/deep/*", async (_request, reply) =>
  reply.code(401).send("Unauthorized"),
);
app.register(fastifyStatic, { root: "/srv/public" });

export { app };
