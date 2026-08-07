import { JSONPath } from "jsonpath-plus";
const records = [{ id: 1, visibility: "public" }];
export function selectRecords(path) {
  return JSONPath({ path, json: records });
}
