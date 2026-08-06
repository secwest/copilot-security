const accounts = [
  {
    _id: 1,
    username: "guest",
    displayName: "Guest",
    mfaSecret: "enrolled-secret",
    role: "guest",
  },
];

function executeWritePipeline(documents, pipeline) {
  let output = documents.map((document) => ({ ...document }));
  for (const stage of pipeline) {
    if (stage.$set) {
      output = output.map((document) => ({ ...document, ...stage.$set }));
    }
    if (stage.$merge?.into === "accounts") {
      for (const result of output) {
        const index = documents.findIndex(({ _id }) => _id === result._id);
        if (index >= 0 && stage.$merge.whenMatched === "replace") {
          documents[index] = { ...result };
        }
      }
    }
  }
}

const attackerStages = [{ $set: { role: "admin", mfaSecret: null } }];
const fixedWriteStage = {
  $merge: {
    into: "accounts",
    on: "_id",
    whenMatched: "replace",
    whenNotMatched: "discard",
  },
};
executeWritePipeline(accounts, [...attackerStages, fixedWriteStage]);
if (accounts[0]?.role !== "admin" || accounts[0]?.mfaSecret !== null) {
  throw new Error("aggregate merge injection not reproduced");
}
console.log("vulnerable aggregate pipeline replaced role and MFA state");
