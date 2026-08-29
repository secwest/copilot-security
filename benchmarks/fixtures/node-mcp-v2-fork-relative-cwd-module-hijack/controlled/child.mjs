if (typeof process.send !== "function") {
  throw new Error("The forked witness requires its private IPC channel.");
}

process.send({ selected: "controlled-relative-child" }, () => {
  process.disconnect();
});
