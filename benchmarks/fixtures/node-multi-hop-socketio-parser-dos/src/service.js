import { decodePacket } from "./storage.js";

export function processPacket(packet) {
  return decodePacket(packet);
}
