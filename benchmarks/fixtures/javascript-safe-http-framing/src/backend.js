export function processCanonicalRequest(request, state) {
  if (request.method === "POST" && request.path === "/submit") {
    state.submissions += 1;
  }
  if (request.method === "DELETE" && request.path === "/admin/records") {
    state.records = [];
    state.adminDeletes += 1;
  }
}
