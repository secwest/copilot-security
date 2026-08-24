import fastUri from "fast-uri";

const baseUrl = "https://allowed.example/";
const reference = "\\\\169.254.169.254/latest/meta-data/";
const policyUrl = fastUri.resolve(baseUrl, reference);
const policyHost = fastUri.parse(policyUrl).host;
const networkHost = new URL(reference, baseUrl).hostname;

if (policyHost !== "allowed.example") {
  throw new Error(`the vulnerable policy selected ${policyHost}`);
}
if (networkHost !== "169.254.169.254") {
  throw new Error(`the network consumer selected ${networkHost}`);
}
console.log("vulnerable fast-uri authority disagreement reproduced");
