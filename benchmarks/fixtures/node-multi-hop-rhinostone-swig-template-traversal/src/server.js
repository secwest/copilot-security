import { selectPartial } from "./service.js";

export function page(request, response) {
  return response.send(selectPartial(request.query.partial));
}
