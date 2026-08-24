import { readFile } from "node:fs/promises";
import { config, list } from "@keystone-6/core";
import { allowAll } from "@keystone-6/core/access";
import { getContext } from "@keystone-6/core/context";
import { text } from "@keystone-6/core/fields";

const maxTake = 3;
const requestedTake = -5;
const rows = Array.from({ length: 8 }, (_, index) => ({
  id: String(index + 1),
  title: `post-${index + 1}`,
}));
let observedTake;

class PrismaClient {
  constructor() {
    this.Post = {
      findMany: async ({ take }) => {
        observedTake = take;
        return take < 0 ? rows.slice(take) : rows.slice(0, take);
      },
    };
  }

  $extends() {
    return this;
  }

  async $disconnect() {}

  async $transaction(callback) {
    return callback(this);
  }
}

const PrismaModule = {
  PrismaClient,
  Prisma: { DbNull: null, JsonNull: null },
};
const keystoneConfig = config({
  db: { provider: "sqlite", url: "file:./unused.db" },
  lists: {
    Post: list({
      access: allowAll,
      graphql: { maxTake },
      fields: { title: text() },
    }),
  },
});
const context = getContext(keystoneConfig, PrismaModule);
const result = await context.graphql.raw({
  query: `{ posts(take: ${requestedTake}) { id title } }`,
});
await context.prisma.$disconnect();

const packageJson = JSON.parse(
  await readFile(
    new URL("./node_modules/@keystone-6/core/package.json", import.meta.url),
    "utf8",
  ),
);
const affected = packageJson.version === "6.5.2";
const returned = result.data?.posts?.length ?? 0;
const errorCode = result.errors?.[0]?.extensions?.code ?? null;
const bypassed = returned > maxTake && observedTake === requestedTake;
const blocked =
  errorCode === "KS_LIMITS_EXCEEDED" && observedTake === undefined;

if ((affected && !bypassed) || (!affected && !blocked)) {
  throw new Error(
    `unexpected maxTake result for Keystone ${packageJson.version}: ${JSON.stringify({ returned, errorCode, observedTake, result })}`,
  );
}

console.log(
  JSON.stringify({
    version: packageJson.version,
    maxTake,
    requestedTake,
    returned,
    observedTake: observedTake ?? null,
    errorCode,
    bypassed,
    blocked,
  }),
);
