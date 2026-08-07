import objectPath from "object-path";
const inherited = objectPath.withInheritedProps;
export function deleteSetting(path) {
  return inherited.del({}, path);
}
