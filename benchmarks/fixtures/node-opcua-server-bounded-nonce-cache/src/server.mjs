import { OPCUAServer } from "node-opcua";

const server = new OPCUAServer({ port: 4840 });
await server.initialize();

await server.start();
