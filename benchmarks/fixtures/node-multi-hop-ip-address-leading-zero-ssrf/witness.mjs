const hostileHost = "012.0.0.1";
const guardAddress = hostileHost
  .split(".")
  .map((part) => Number.parseInt(part, 10));
const guardSeesPrivate = guardAddress[0] === 10;
const networkHost = new URL(`http://${hostileHost}/`).hostname;

if (guardSeesPrivate || guardAddress.join(".") !== "12.0.0.1") {
  throw new Error("the vulnerable decimal guard did not allow the host");
}
if (networkHost !== "10.0.0.1") {
  throw new Error("the WHATWG URL parser did not select the private host");
}
console.log("vulnerable decimal/octal ip-address disagreement reproduced");
