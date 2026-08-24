import { processPacket } from "./service.js";

export function ingestPacket(packet) {
  return processPacket(packet);
}
