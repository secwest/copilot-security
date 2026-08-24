import fastUri from "fast-uri";

const BASE_URL = "https://allowed.example/";

export async function fetchProfile(reference) {
  const policyUrl = fastUri.resolve(BASE_URL, reference);
  const policyHost = fastUri.parse(policyUrl).host;
  if (policyHost !== "allowed.example") throw new Error("untrusted host");
  return fetch(new URL(reference, BASE_URL));
}
