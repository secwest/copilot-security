if (typeof process.send !== "function") {
  throw new Error("The forked witness requires its private IPC channel.");
}

process.send(
  { selected: "fixture-local-selected-module", argv: process.argv.slice(2) },
  () => {
    process.disconnect();
  },
);
