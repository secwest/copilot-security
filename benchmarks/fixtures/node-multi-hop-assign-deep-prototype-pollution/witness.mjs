function isObject(value) {
  return (
    typeof value === "function" ||
    Object.prototype.toString.call(value) === "[object Object]"
  );
}

function representative047AssignDeep(target, ...sources) {
  target = target || {};
  for (const source of sources) {
    if (!isObject(source)) continue;
    for (const key in source) {
      if (
        key === "__proto__" ||
        !Object.prototype.hasOwnProperty.call(source, key)
      ) {
        continue;
      }
      const value = source[key];
      if (isObject(value)) {
        if (target[key] === undefined && typeof value === "function") {
          target[key] = value;
        }
        target[key] = representative047AssignDeep(target[key] || {}, value);
      } else {
        target[key] = value;
      }
    }
  }
  return target;
}

const patch = JSON.parse(
  '{"constructor":{"prototype":{"isAdministrator":true}}}',
);
try {
  let lateAssignmentError;
  try {
    representative047AssignDeep({}, patch);
  } catch (error) {
    lateAssignmentError = error;
  }
  if ({}.isAdministrator !== true) {
    throw new Error(
      "assign-deep 0.4.7 semantics did not modify Object.prototype",
    );
  }
  if (!(lateAssignmentError instanceof TypeError)) {
    throw new Error(
      "assign-deep 0.4.7 semantics did not reach the expected late assignment failure",
    );
  }
  console.log(
    "assign-deep 0.4.7 semantics modified Object.prototype before the late assignment failed",
  );
} finally {
  delete Object.prototype.isAdministrator;
}
