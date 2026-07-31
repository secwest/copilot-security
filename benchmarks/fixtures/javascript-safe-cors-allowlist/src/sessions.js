export const sessionCookie = Object.freeze({
  httpOnly: true,
  sameSite: "lax",
  secure: true,
});

export function createSessionStore(records) {
  const byId = new Map(records.map((record) => [record.id, { ...record }]));

  return Object.freeze({
    get(sessionId) {
      const session = byId.get(sessionId);
      return session ? Object.freeze({ ...session }) : null;
    },
  });
}
