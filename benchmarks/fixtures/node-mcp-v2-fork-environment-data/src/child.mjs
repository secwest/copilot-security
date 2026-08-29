if (typeof process.send !== "function") {
  throw new Error("The forked control requires its private IPC channel.");
}

process.send(
  {
    preload: globalThis.__copilotSecurityInertPreload ?? null,
    data: process.env.COPILOT_SECURITY_NODE_OPTIONS_DATA,
  },
  () => {
    process.disconnect();
  },
);
