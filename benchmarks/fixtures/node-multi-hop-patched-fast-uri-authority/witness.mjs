import fastUri from "fast-uri";

const baseUrl = "https://allowed.example/";
const reference = "\\\\169.254.169.254/latest/meta-data/";

try {
  fastUri.resolve(baseUrl, reference);
} catch {
  console.log("patched fast-uri authority rejection reproduced");
  process.exit(0);
}
throw new Error("the repaired resolver accepted the malformed authority");
