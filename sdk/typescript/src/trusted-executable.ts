import { constants } from "node:fs";
import { access, lstat, readFile, realpath, stat } from "node:fs/promises";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";

export interface TrustedExecutable {
  executable: string;
  environment: Record<string, string | undefined>;
}

const MAX_WINDOWS_WRAPPER_BYTES = 16 * 1024;

export async function resolveTrustedExecutable(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string,
): Promise<TrustedExecutable | null> {
  const root = await realpath(protectedRoot).catch(() =>
    resolve(protectedRoot),
  );
  const path = Object.entries(environment).find(
    ([name]) => name.toUpperCase() === "PATH",
  )?.[1];
  const entries: string[] = [];
  for (const entry of path?.split(delimiter) ?? []) {
    if (entry.length === 0 || !isAbsolute(entry)) continue;
    const canonical = await realpath(entry).catch(() => null);
    if (canonical === null || isWithin(root, canonical)) continue;
    if (!entries.includes(canonical)) entries.push(canonical);
  }

  // execFile cannot launch batch files, but their symlink targets still affect PATH trust.
  const extensions =
    process.platform === "win32"
      ? /\.(?:exe|com)$/iu.test(candidate)
        ? [{ suffix: "", runnable: true }]
        : [
            { suffix: ".exe", runnable: true },
            { suffix: ".com", runnable: true },
            { suffix: ".bat", runnable: false },
            { suffix: ".cmd", runnable: false },
            { suffix: "", runnable: false },
          ]
      : [{ suffix: "", runnable: true }];
  const pathLike = candidate.includes("/") || candidate.includes("\\");
  const candidates = pathLike
    ? [{ entry: null, path: resolve(candidate), runnable: true }]
    : entries.flatMap((entry) =>
        extensions.map((extension) => ({
          entry,
          path: join(entry, `${candidate}${extension.suffix}`),
          runnable: extension.runnable,
        })),
      );
  const unsafeEntries = new Set<string>();
  let executable: string | null = null;
  for (const current of candidates) {
    const canonical = await realpath(current.path).catch(() => null);
    if (canonical === null) continue;
    if (isWithin(root, canonical)) {
      if (current.entry !== null) unsafeEntries.add(current.entry);
      continue;
    }
    if (!current.runnable) continue;
    try {
      await access(
        canonical,
        process.platform === "win32" ? constants.F_OK : constants.X_OK,
      );
      if (!(await stat(canonical)).isFile()) continue;
      executable ??= pathLike ? canonical : current.path;
    } catch {
      continue;
    }
  }
  if (executable === null) return null;

  const sanitizedEnvironment = { ...environment };
  for (const name of Object.keys(sanitizedEnvironment)) {
    if (name.toUpperCase() === "PATH") delete sanitizedEnvironment[name];
  }
  sanitizedEnvironment["PATH"] = entries
    .filter((entry) => !unsafeEntries.has(entry))
    .join(delimiter);
  return { executable, environment: sanitizedEnvironment };
}

export async function resolveTrustedWindowsCommandWrapper(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string,
): Promise<TrustedExecutable | null> {
  if (process.platform !== "win32" || /[\\/]/u.test(candidate)) return null;
  const path = Object.entries(environment).find(
    ([name]) => name.toUpperCase() === "PATH",
  )?.[1];
  for (const entry of path?.split(delimiter) ?? []) {
    if (!isAbsolute(entry)) continue;
    const wrapper = join(entry, `${candidate}.cmd`);
    const metadata = await lstat(wrapper).catch(() => null);
    if (
      metadata === null ||
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.size > MAX_WINDOWS_WRAPPER_BYTES
    ) {
      continue;
    }
    const contents = await readFile(wrapper, "utf8");
    const invocation = contents
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .find((line) => line.length > 0 && !/^@?echo off$/iu.test(line));
    const escapedCandidate = candidate.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const match = new RegExp(
      `^"([^"\\r\\n]+\\\\${escapedCandidate}\\.exe)"\\s+%\\*$`,
      "iu",
    ).exec(invocation ?? "");
    if (match?.[1] === undefined) continue;
    const executable = await realpath(resolve(match[1])).catch(() => null);
    if (executable === null) continue;
    const trusted = await resolveTrustedExecutable(
      executable,
      environment,
      protectedRoot,
    );
    if (trusted !== null) return trusted;
  }
  return null;
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}
