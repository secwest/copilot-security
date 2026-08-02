export function createBestEffortWriter(
  stream: NodeJS.WritableStream & { destroyed?: boolean },
): (chunk: string | Uint8Array) => boolean;
