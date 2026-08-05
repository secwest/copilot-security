import { createWorkspaceSession } from "./session.js";

export function dispatchWorkspaceAgent(persona, question) {
  return createWorkspaceSession(persona, question);
}
