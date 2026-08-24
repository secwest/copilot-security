import { Decoder } from "socket.io-parser";

const decoder = new Decoder();

export function decodePacket(packet) {
  decoder.add(packet);
}
