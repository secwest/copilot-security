import { extractArticle } from "./extract-article.js";

export async function clipArticle(request, response) {
  const html = request.body.html;
  const url = request.body.url;
  const extracted = await extractArticle(html, url);
  response.type("html").send(extracted.content);
}
