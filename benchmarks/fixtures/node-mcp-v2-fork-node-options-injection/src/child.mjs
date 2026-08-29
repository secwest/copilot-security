if (typeof process.send !== "function") {
  throw new Error("The forked witness requires its private IPC channel.");
}

process.send(
  { preload: globalThis.__copilotSecurityInertPreload ?? null },
  () => {
    process.disconnect();
  },
);
