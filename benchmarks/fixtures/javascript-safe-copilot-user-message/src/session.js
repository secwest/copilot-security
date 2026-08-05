import { CopilotClient } from "@github/copilot-sdk";

const client = new CopilotClient();

export async function createWorkspaceSession(persona, question) {
  const session = await client.createSession({
    systemMessage: {
      mode: "append",
      content:
        "Help users understand the selected workspace without changing files.",
    },
  });
  return session.sendAndWait({
    prompt: `Requested persona: ${persona}\nQuestion: ${question}`,
  });
}
