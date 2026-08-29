if (typeof process.send !== "function") {
  throw new Error("The forked witness requires its private IPC channel.");
}

process.send(
  { execPath: process.execPath, argv: process.argv.slice(2) },
  () => {
    process.disconnect();
  },
);
