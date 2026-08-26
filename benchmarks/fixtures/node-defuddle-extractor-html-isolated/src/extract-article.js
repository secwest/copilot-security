import { Defuddle } from "defuddle/node";

export async function extractArticle(html, url) {
  return Defuddle(html, url);
}
