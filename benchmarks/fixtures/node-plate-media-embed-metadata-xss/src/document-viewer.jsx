import { MediaEmbedPlugin } from "@platejs/media/react";
import { Plate } from "platejs/react";
import { MediaEmbedElement } from "./media-embed-node.jsx";

const plugins = [MediaEmbedPlugin.withComponent(MediaEmbedElement)];

export function DocumentViewer(props) {
  return <Plate plugins={plugins} value={props.document} />;
}
