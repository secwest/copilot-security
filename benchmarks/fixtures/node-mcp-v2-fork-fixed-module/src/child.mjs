if (typeof process.send !== "function") {
  throw new Error("The forked control requires its private IPC channel.");
}

process.send({ selected: "fixed-module", argv: process.argv.slice(2) }, () => {
  process.disconnect();
});
