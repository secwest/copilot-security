import { parseVideoUrl } from "@platejs/media";
import { useMediaState } from "@platejs/media/react";

export function MediaEmbedElement(props) {
  const { embed, isVideo } = useMediaState({
    urlParsers: [parseVideoUrl],
  });
  if (!embed || !isVideo) return null;
  return <iframe title="Embedded media" src={embed.url} />;
}
