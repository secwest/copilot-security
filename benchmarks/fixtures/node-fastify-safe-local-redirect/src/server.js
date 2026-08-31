import Fastify from "fastify";

const app = Fastify();

app.get("/continue", (request, reply) => {
  const target = request.query.next;
  return reply.redirect("/continue/" + encodeURIComponent(target));
});

export default app;
