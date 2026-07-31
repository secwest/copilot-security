const TRUSTED_WEBSOCKET_ORIGINS = new Set(["https://portal.example.test"]);

export function openAccountSocket(request, socket, sessions, apiKeys) {
  const origin = String(request.headers.origin ?? "");
  if (!TRUSTED_WEBSOCKET_ORIGINS.has(origin)) {
    socket.close(4403, "origin_not_allowed");
    return false;
  }
  const session = sessions.get(String(request.cookies.sid ?? ""));
  if (!session) {
    socket.close(4401, "unauthorized");
    return false;
  }

  socket.on("message", (raw) => {
    const encoded = String(raw);
    if (encoded.length > 1024) return socket.close(1009, "message_too_big");
    let message;
    try {
      message = JSON.parse(encoded);
    } catch {
      return socket.send(JSON.stringify({ error: "invalid_message" }));
    }
    if (message?.action !== "list-api-keys") {
      return socket.send(JSON.stringify({ error: "unsupported_action" }));
    }
    return socket.send(
      JSON.stringify({
        accountId: session.accountId,
        keys: apiKeys.forAccount(session.accountId),
      }),
    );
  });
  socket.send(JSON.stringify({ type: "ready", accountId: session.accountId }));
  return true;
}
