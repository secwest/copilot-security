if (typeof process.send !== "function") {
  throw new Error("The forked control requires its private IPC channel.");
}

process.send({ selected: "fixed-absolute-child" }, () => {
  process.disconnect();
});
