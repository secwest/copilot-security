import { deliverRawMessage } from "./mailer.js";

export function submitRawMessage(message) {
  return deliverRawMessage(message);
}
