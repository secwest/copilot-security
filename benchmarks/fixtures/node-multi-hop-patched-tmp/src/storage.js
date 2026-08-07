import { writeFileSync } from "node:fs";
import tmp from "tmp";

export function storeExport(prefix, contents) {
  const target = tmp.fileSync({ prefix });
  writeFileSync(target.fd, contents);
  return target;
}
