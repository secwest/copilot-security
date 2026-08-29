if (typeof process.send !== "function") {
  throw new Error("The alternate child requires its private IPC channel.");
}

process.send({ selected: "alternate-relative-child" }, () => {
  process.disconnect();
});
