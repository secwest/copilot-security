import { constants } from "node:fs";
import {
  lstat,
  mkdtemp,
  opendir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join, resolve } from "node:path";
import { Worker } from "node:worker_threads";
import { unzipSync } from "fflate";

const SUPPORTED_EXTENSIONS = new Set([
  ".md",
  ".markdown",
  ".txt",
  ".pdf",
  ".docx",
]);
export const KNOWLEDGE_BASE_LIMITS = Object.freeze({
  paths: 256,
  documents: 256,
  directoryDepth: 32,
  directoryEntries: 100_000,
  documentBytes: 16 * 1024 * 1024,
  totalDocumentBytes: 64 * 1024 * 1024,
  totalExtractedBytes: 64 * 1024 * 1024,
  pdfPages: 512,
  pdfTextItems: 1_000_000,
  pdfDecodeTimeoutMilliseconds: 60_000,
  pdfWorkerMemoryMegabytes: 256,
});

export interface PreparedKnowledgeBase {
  path: string;
  sources: string[];
  cleanup(): Promise<void>;
}

export async function prepareKnowledgeBase(
  paths: readonly string[],
  signal?: AbortSignal,
): Promise<PreparedKnowledgeBase> {
  if (paths.length > KNOWLEDGE_BASE_LIMITS.paths) {
    throw new Error(
      `Knowledge base accepts at most ${KNOWLEDGE_BASE_LIMITS.paths} paths.`,
    );
  }
  const sources = new Set<string>();
  const documents = new Set<string>();
  const discovery = { entries: 0, documents: new Set<string>() };

  for (const requested of paths) {
    signal?.throwIfAborted();
    if (!requested.trim())
      throw new Error("Knowledge base paths cannot be empty.");
    const path = resolve(requested);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(`Knowledge base paths cannot be symbolic links: ${path}`);
    }
    if (!metadata.isFile() && !metadata.isDirectory()) {
      throw new Error(
        `Knowledge base path is not a file or directory: ${path}`,
      );
    }

    const source = await realpath(path);
    if (sources.has(source)) continue;
    sources.add(source);
    const selected = metadata.isDirectory()
      ? await discover(source, discovery, signal)
      : [source];
    if (selected.length === 0) {
      throw new Error(
        `Knowledge base directory contains no supported documents: ${path}`,
      );
    }
    for (const document of selected) {
      if (!SUPPORTED_EXTENSIONS.has(extname(document).toLowerCase())) {
        throw new Error(`Unsupported knowledge base document: ${document}`);
      }
      documents.add(document);
      if (documents.size > KNOWLEDGE_BASE_LIMITS.documents) {
        throw new Error(
          `Knowledge base accepts at most ${KNOWLEDGE_BASE_LIMITS.documents} documents.`,
        );
      }
    }
  }

  const path = await mkdtemp(join(tmpdir(), "copilot-security-knowledge-"));
  try {
    let index = 0;
    let totalDocumentBytes = 0;
    let totalExtractedBytes = 0;
    for (const document of [...documents].sort()) {
      signal?.throwIfAborted();
      const metadata = await lstat(document);
      if (metadata.isSymbolicLink() || !metadata.isFile()) {
        throw new Error(
          `Knowledge base document must remain a regular non-symlink file: ${document}`,
        );
      }
      if (process.platform !== "win32" && (metadata.mode & 0o444) === 0) {
        throw new Error(`Knowledge base document is not readable: ${document}`);
      }
      requireDocumentSize(document, metadata.size);
      const bytes = await readFile(document, {
        flag: constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
        signal,
      });
      requireDocumentSize(document, bytes.byteLength);
      totalDocumentBytes += bytes.byteLength;
      if (totalDocumentBytes > KNOWLEDGE_BASE_LIMITS.totalDocumentBytes) {
        throw new Error(
          `Knowledge base source documents exceed the ${KNOWLEDGE_BASE_LIMITS.totalDocumentBytes}-byte aggregate limit.`,
        );
      }
      const extension = extname(document).toLowerCase();
      const text =
        extension === ".pdf"
          ? await extractPdf(document, bytes, signal)
          : extension === ".docx"
            ? extractDocx(document, bytes)
            : decodeText(document, bytes);
      if ((extension === ".pdf" || extension === ".docx") && !text.trim()) {
        throw new Error(
          `Knowledge base document contains no extractable text: ${document}`,
        );
      }
      totalExtractedBytes += Buffer.byteLength(text, "utf8");
      if (totalExtractedBytes > KNOWLEDGE_BASE_LIMITS.totalExtractedBytes) {
        throw new Error(
          `Knowledge base extracted text exceeds the ${KNOWLEDGE_BASE_LIMITS.totalExtractedBytes}-byte aggregate limit.`,
        );
      }
      await writeFile(
        join(path, `${index++}-${basename(document)}.txt`),
        text,
        {
          encoding: "utf8",
          mode: 0o600,
          signal,
        },
      );
    }
  } catch (error) {
    await rm(path, { recursive: true, force: true });
    throw error;
  }

  return {
    path,
    sources: [...sources],
    cleanup: () => rm(path, { recursive: true, force: true }),
  };
}

async function discover(
  directory: string,
  state: { entries: number; documents: Set<string> },
  signal?: AbortSignal,
  depth = 0,
): Promise<string[]> {
  if (depth > KNOWLEDGE_BASE_LIMITS.directoryDepth) {
    throw new Error(
      `Knowledge base directory nesting exceeds ${KNOWLEDGE_BASE_LIMITS.directoryDepth} levels: ${directory}`,
    );
  }
  const documents: string[] = [];
  const entries = await opendir(directory);
  for await (const entry of entries) {
    signal?.throwIfAborted();
    state.entries += 1;
    if (state.entries > KNOWLEDGE_BASE_LIMITS.directoryEntries) {
      throw new Error(
        `Knowledge base directory traversal exceeds ${KNOWLEDGE_BASE_LIMITS.directoryEntries} entries.`,
      );
    }
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      documents.push(...(await discover(path, state, signal, depth + 1)));
    } else if (
      entry.isFile() &&
      SUPPORTED_EXTENSIONS.has(extname(path).toLowerCase())
    ) {
      state.documents.add(path);
      if (state.documents.size > KNOWLEDGE_BASE_LIMITS.documents) {
        throw new Error(
          `Knowledge base accepts at most ${KNOWLEDGE_BASE_LIMITS.documents} documents.`,
        );
      }
      documents.push(path);
    }
  }
  return documents;
}

function requireDocumentSize(path: string, size: number): void {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error(`Knowledge base document has an invalid size: ${path}`);
  }
  if (size > KNOWLEDGE_BASE_LIMITS.documentBytes) {
    throw new Error(
      `Knowledge base document exceeds the ${KNOWLEDGE_BASE_LIMITS.documentBytes}-byte limit: ${path}`,
    );
  }
}

function decodeText(path: string, bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(`Knowledge base document is not valid UTF-8: ${path}`, {
      cause: error,
    });
  }
}

const PDF_WORKER_SOURCE = String.raw`
const { parentPort, workerData } = require("node:worker_threads");
(async () => {
  let document;
  try {
    const { getDocument, VerbosityLevel } = await import(workerData.moduleUrl);
    document = await getDocument({
      data: workerData.bytes,
      disableFontFace: true,
      isEvalSupported: false,
      stopAtErrors: true,
      useSystemFonts: false,
      verbosity: VerbosityLevel.ERRORS,
    }).promise;
    if (document.numPages > workerData.limits.pdfPages) {
      throw new Error("PDF page count exceeds the configured limit.");
    }
    const pages = [];
    let extractedBytes = 0;
    let textItems = 0;
    for (let number = 1; number <= document.numPages; number += 1) {
      const page = await document.getPage(number);
      const content = await page.getTextContent();
      textItems += content.items.length;
      if (textItems > workerData.limits.pdfTextItems) {
        throw new Error("PDF text-item count exceeds the configured limit.");
      }
      const text = content.items
        .map((item) => ("str" in item ? item.str : ""))
        .join(" ");
      extractedBytes += Buffer.byteLength(text, "utf8") + 1;
      if (extractedBytes > workerData.limits.totalExtractedBytes) {
        throw new Error("PDF extracted text exceeds the configured byte limit.");
      }
      pages.push(text);
      page.cleanup();
    }
    parentPort.postMessage({ ok: true, text: pages.join("\n") });
  } catch (error) {
    parentPort.postMessage({
      ok: false,
      message: error instanceof Error ? error.message : String(error),
    });
  } finally {
    if (document !== undefined) await document.destroy().catch(() => undefined);
  }
})().catch((error) => {
  parentPort.postMessage({
    ok: false,
    message: error instanceof Error ? error.message : String(error),
  });
});
`;

async function extractPdf(
  path: string,
  bytes: Uint8Array,
  signal?: AbortSignal,
): Promise<string> {
  try {
    signal?.throwIfAborted();
    const transferable = new Uint8Array(bytes);
    const worker = new Worker(PDF_WORKER_SOURCE, {
      eval: true,
      workerData: {
        bytes: transferable,
        moduleUrl: import.meta.resolve("pdfjs-dist/legacy/build/pdf.mjs"),
        limits: KNOWLEDGE_BASE_LIMITS,
      },
      transferList: [transferable.buffer],
      resourceLimits: {
        maxOldGenerationSizeMb: KNOWLEDGE_BASE_LIMITS.pdfWorkerMemoryMegabytes,
        maxYoungGenerationSizeMb: 32,
        stackSizeMb: 4,
      },
    });
    return await new Promise<string>((resolveText, rejectText) => {
      let settled = false;
      const finish = (error: Error | null, text = ""): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        signal?.removeEventListener("abort", abort);
        void worker.terminate();
        if (error === null) resolveText(text);
        else rejectText(error);
      };
      const abort = (): void =>
        finish(new Error("PDF extraction was interrupted."));
      const timeout = setTimeout(
        () => finish(new Error("PDF extraction exceeded its decode deadline.")),
        KNOWLEDGE_BASE_LIMITS.pdfDecodeTimeoutMilliseconds,
      );
      timeout.unref();
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted === true) abort();
      worker.once("message", (message: unknown) => {
        if (
          typeof message === "object" &&
          message !== null &&
          "ok" in message &&
          message.ok === true &&
          "text" in message &&
          typeof message.text === "string"
        ) {
          finish(null, message.text);
          return;
        }
        const detail =
          typeof message === "object" &&
          message !== null &&
          "message" in message &&
          typeof message.message === "string"
            ? message.message
            : "PDF decoder returned an invalid response.";
        finish(new Error(detail));
      });
      worker.once("error", (error) => finish(error));
      worker.once("exit", (code) => {
        if (code !== 0) {
          finish(new Error(`PDF decoder exited with status ${code}.`));
        }
      });
    });
  } catch (error) {
    if (signal?.aborted === true) signal.throwIfAborted();
    throw new Error(`Cannot extract text from knowledge base PDF: ${path}`, {
      cause: error,
    });
  }
}

function extractDocx(path: string, bytes: Uint8Array): string {
  try {
    const files = unzipSync(bytes, {
      filter: (file) => {
        if (file.name !== "word/document.xml") return false;
        if (file.originalSize > 25 * 1024 * 1024) {
          throw new Error("DOCX document text exceeds 25 MB.");
        }
        return true;
      },
    });
    const document = files["word/document.xml"];
    if (document === undefined) throw new Error("Missing word/document.xml.");
    const xml = decodeText(path, document);
    if (
      !/<(?:\w+:)?document\b[^>]*>[\s\S]*<\/(?:\w+:)?document\s*>/u.test(xml)
    ) {
      throw new Error("Malformed word/document.xml.");
    }
    return unescapeXmlEntities(
      xml
        .replace(/<\/(?:\w+:)?p\s*>/gu, "\n")
        .replace(/<(?:\w+:)?tab\b[^>]*\/>/gu, "\t")
        .replace(/<[^>]+>/gu, ""),
    );
  } catch (error) {
    throw new Error(`Cannot extract text from knowledge base DOCX: ${path}`, {
      cause: error,
    });
  }
}

function unescapeXmlEntities(value: string): string {
  const entities: Record<string, string> = {
    amp: "&",
    lt: "<",
    gt: ">",
    quot: '"',
    apos: "'",
  };
  return value.replace(
    /&(amp|lt|gt|quot|apos|#\d+|#x[\da-f]+);/giu,
    (entity, name: string) => {
      if (!name.startsWith("#")) return entities[name.toLowerCase()] ?? entity;
      const hexadecimal = name[1]?.toLowerCase() === "x";
      return String.fromCodePoint(
        Number.parseInt(name.slice(hexadecimal ? 2 : 1), hexadecimal ? 16 : 10),
      );
    },
  );
}
