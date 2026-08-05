import { dispatchWorkspaceAgent } from "./service.js";

export async function workspaceAgent(request, response) {
  const persona = String(request.query.persona ?? "");
  const question = String(request.query.question ?? "");
  const result = await dispatchWorkspaceAgent(persona, question);
  return response.json({ result });
}
