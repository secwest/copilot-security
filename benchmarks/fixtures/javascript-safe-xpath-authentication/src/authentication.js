const ACCOUNT_EXPRESSION =
  "/users/user[username/text()=$username and passwordVerifier/text()=$passwordVerifier]";

export function authenticateDirectoryUser(directory, credentials) {
  if (
    typeof credentials?.username !== "string" ||
    typeof credentials?.passwordVerifier !== "string" ||
    credentials.username.length === 0 ||
    credentials.username.length > 128 ||
    credentials.passwordVerifier.length === 0 ||
    credentials.passwordVerifier.length > 256
  ) {
    return null;
  }

  return directory.selectOne(ACCOUNT_EXPRESSION, {
    username: credentials.username,
    passwordVerifier: credentials.passwordVerifier,
  });
}
