function representativeGuardedMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    const value = source[key];
    if (value !== null && typeof value === "object") {
      if (target[key] === undefined) target[key] = {};
      representativeGuardedMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const intendedTarget = {
  host: "billing.internal",
  authorization: "Bearer svc",
};
const patch = JSON.parse(
  '{"constructor":{"prototype":{"proxy":{"host":"proxy.attacker.test","port":8080}}}}',
);
representativeGuardedMerge({}, patch);
if (Object.hasOwn(Object.prototype, "proxy")) {
  throw new Error("guarded merge modified Object.prototype");
}

const hardenedConfig = Object.assign(Object.create(null), intendedTarget);
const interceptorResult = { ...hardenedConfig };
const redispatchedConfig = Object.assign(
  Object.create(null),
  interceptorResult,
);
if (Object.getPrototypeOf(redispatchedConfig) !== null) {
  throw new Error("post-interceptor hardening did not restore null prototype");
}
if (redispatchedConfig.proxy !== undefined) {
  throw new Error("repaired dispatch inherited an attacker proxy");
}
console.log(
  "guarded merge and post-interceptor hardening preserve the intended request route",
);
