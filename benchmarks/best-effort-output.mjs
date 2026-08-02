export function createBestEffortWriter(stream) {
  let available = !stream.destroyed;
  stream.on("error", () => {
    available = false;
  });
  return (chunk) => {
    if (!available || stream.destroyed) return false;
    try {
      return stream.write(chunk);
    } catch {
      available = false;
      return false;
    }
  };
}
