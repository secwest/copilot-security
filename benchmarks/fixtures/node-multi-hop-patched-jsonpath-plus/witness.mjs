const payload =
  '$[?(@root.toString.__lookupGetter__("__proto__").call(@root.toString).constructor("return process.version")())]';

function representativeSafeEval(path) {
  if (path.includes("__lookupGetter__")) {
    throw new Error("Use of __lookupGetter__ is not permitted");
  }
  return [];
}

try {
  representativeSafeEval(payload);
  throw new Error("jsonpath-plus 10.4.0 evaluator semantics accepted payload");
} catch (error) {
  if (!String(error).includes("__lookupGetter__ is not permitted")) throw error;
}
console.log("jsonpath-plus 10.4.0 evaluator semantics blocked accessor lookup");
