import express from "express";
import { routeStudentLookup } from "./gateway.js";

const app = express();

app.get("/students", async (request, response) => {
  const firstName = request.query.firstName;
  const student = await routeStudentLookup(firstName);
  response.json(student);
});
