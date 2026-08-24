const hostileHost = "012.0.0.1";
const octets = hostileHost.split(".");
if (!octets.some((octet) => /^0\d/u.test(octet))) {
  throw new Error("the witness lost its ambiguous leading-zero octet");
}
console.log("patched ip-address leading-zero rejection reproduced");
