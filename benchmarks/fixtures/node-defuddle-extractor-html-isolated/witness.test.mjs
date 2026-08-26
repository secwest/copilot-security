import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Defuddle } from "defuddle/node";
import { parseHTML } from "linkedom";

const articleUrl = "https://x.com/testuser/article/123456789";
const sentinel = "copilot_security_defuddle_marker";
const maliciousHtml = `
  <html><head><title>Test Article</title></head><body>
    <div data-testid="twitterArticleReadView">
      <div data-testid="tweetPhoto">
        <img src="https://example.test/header.jpg" alt='x" onerror="${sentinel}=1'>
      </div>
      <div data-testid="twitterArticleRichTextView">
        <h1 data-testid="twitter-article-title">Test Article</h1>
        <div class="public-DraftStyleDefault-block">Body text</div>
      </div>
    </div>
  </body></html>`;

const packagePath = fileURLToPath(import.meta.resolve("defuddle/package.json"));
const metadata = JSON.parse(await readFile(packagePath, "utf8"));

test("site-extractor output cannot create an executable attribute", async () => {
  const result = await Defuddle(maliciousHtml, articleUrl, {
    useAsync: false,
  });
  const { document } = parseHTML(`<body>${result.content}</body>`);
  const executableAttributes = [...document.querySelectorAll("*")].flatMap(
    (element) =>
      [...element.attributes]
        .filter((attribute) => attribute.name.toLowerCase().startsWith("on"))
        .map((attribute) => `${attribute.name}=${attribute.value}`),
  );
  const retainedSentinel = executableAttributes.some((attribute) =>
    attribute.includes(sentinel),
  );
  expect(retainedSentinel).toBe(metadata.version === "0.19.0");
  console.log(
    JSON.stringify({
      version: metadata.version,
      extractorType: result.extractorType ?? null,
      retainedSentinel,
      executableAttributeCount: executableAttributes.length,
    }),
  );
});
