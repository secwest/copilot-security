import { createServer } from "node:http";
import { Server } from "socket.io";

const httpServer = createServer();
export const io = new Server(httpServer, { transports: ["websocket"] });
httpServer.listen(3000, "127.0.0.1");
