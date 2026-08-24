import { findStudent } from "./storage.js";

export async function lookupStudent(firstName) {
  return findStudent(firstName);
}
