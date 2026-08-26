import SUNEDITOR from "suneditor";
import { embed } from "suneditor/plugins";

export function mountEditor(request) {
  return SUNEDITOR.create("editor", {
    plugins: { embed },
    buttonList: [["embed"]],
    value: request.body.html,
  });
}
