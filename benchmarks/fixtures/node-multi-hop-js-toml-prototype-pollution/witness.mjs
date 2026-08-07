function representativeLoad(text, safe) {
  const root = safe ? Object.create(null) : {};
  const section = /^\[([^\]]+)\]/mu.exec(text)?.[1];
  const property = /^([A-Za-z_$][\w$]*)\s*=\s*(true|false)$/mu.exec(text);
  if (section === undefined || property === null) return root;
  const table = safe ? Object.create(null) : root[section] || {};
  root[section] = table;
  table[property[1]] = property[2] === "true";
  return root;
}

const hostile = "[__proto__]\nisAdmin = true\n";
try {
  representativeLoad(hostile, false);
  if ({}.isAdmin !== true) {
    throw new Error("js-toml 1.0.1 semantics did not modify Object.prototype");
  }
  console.log("js-toml 1.0.1 parser semantics modified Object.prototype");
} finally {
  delete Object.prototype.isAdmin;
}

const safe = representativeLoad(hostile, true);
if (Object.getPrototypeOf(safe) !== null || {}.isAdmin !== undefined) {
  throw new Error("js-toml 1.0.2 null-prototype semantics were not preserved");
}
console.log("js-toml 1.0.2 null-prototype semantics retained hostile key data");
