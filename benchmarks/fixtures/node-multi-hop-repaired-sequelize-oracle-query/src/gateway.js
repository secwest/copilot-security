import { lookupStudent } from "./service.js";

export async function routeStudentLookup(firstName) {
  return lookupStudent(firstName);
}
