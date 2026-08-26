import { expect, mock, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

const serializedNode = {
  type: "media_embed",
  provider: "vimeo",
  sourceUrl: "https://vimeo.com/1",
  url: "javascript:parent.postMessage('plate-media-xss','*')",
  children: [{ text: "" }],
};

const actualPlateReact = await import("platejs/react");
mock.module("platejs/react", () => ({
  ...actualPlateReact,
  useEditorRef: () => ({ getType: (key) => key }),
  useElement: () => serializedNode,
  useFocused: () => false,
  useReadOnly: () => true,
  useSelected: () => false,
}));

const { parseVideoUrl } = await import("@platejs/media");
const { useMediaState } = await import("@platejs/media/react");
const packagePath = fileURLToPath(
  import.meta.resolve("@platejs/media/package.json"),
);
const metadata = JSON.parse(await readFile(packagePath, "utf8"));

test("serialized media metadata cannot bypass URL parsing", () => {
  let observed;
  function Probe() {
    observed = useMediaState({ urlParsers: [parseVideoUrl] });
    return React.createElement("span", null, "bounded-plate-witness");
  }

  renderToStaticMarkup(React.createElement(Probe));
  const retainedUnsafeUrl =
    observed?.embed?.provider === "vimeo" &&
    observed?.embed?.url === serializedNode.url;
  const expectedAffected = metadata.version === "53.0.1";
  expect(retainedUnsafeUrl).toBe(expectedAffected);
  console.log(
    JSON.stringify({
      version: metadata.version,
      provider: observed?.embed?.provider ?? null,
      retainedUnsafeUrl,
      isVideo: observed?.isVideo ?? false,
    }),
  );
});
