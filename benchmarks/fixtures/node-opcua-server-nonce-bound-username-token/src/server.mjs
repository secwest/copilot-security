import { OPCUAServer } from "node-opcua";

const userManager = {
  isValidUser(userName, password) {
    return userName === "operator" && password === "correct horse";
  },
};
const server = new OPCUAServer({ port: 4840, userManager });
await server.initialize();

await server.start();
