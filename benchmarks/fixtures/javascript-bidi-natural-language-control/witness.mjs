import assert from "node:assert/strict";
import { canDeleteDocument } from "./src/authorize.js";

const outsider = { id: "attacker", isAdmin: false };
const protectedDocument = { ownerId: "victim" };

assert.equal(canDeleteDocument(outsider, protectedDocument), false);
