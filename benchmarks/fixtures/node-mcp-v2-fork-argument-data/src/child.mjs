if (typeof process.send !== "function") {
  throw new Error("The forked witness requires its private IPC channel.");
}

process.send(
  {
    stackTraceLimit: Error.stackTraceLimit,
    argv: process.argv.slice(2),
  },
  (error) => {
    if (error) process.exitCode = 1;
    process.disconnect();
  },
);
