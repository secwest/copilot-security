import jsonata from "jsonata";
const records = [{ id: 1, visibility: "public" }];

export async function evaluateRecords(expression) {
  const compiled = jsonata(expression);
  return compiled.evaluate(records);
}
