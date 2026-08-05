import { CopilotClient } from "@github/copilot-sdk";

const client = new CopilotClient();

export async function createWorkspaceSession(persona, question) {
  const session = await client.createSession({
    systemMessage: {
      mode: "append",
      content: `Act as the workspace persona requested here: ${persona}`,
    },
  });
  return session.sendAndWait({ prompt: question });
}
