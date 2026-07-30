const ACCOUNT_NAME = /^[a-z][a-z0-9._-]{0,63}$/u;

export function authenticateDirectoryUser(directory, credentials) {
  if (
    typeof credentials?.username !== "string" ||
    typeof credentials?.passwordVerifier !== "string" ||
    !ACCOUNT_NAME.test(credentials.username) ||
    credentials.passwordVerifier.length === 0 ||
    credentials.passwordVerifier.length > 256
  ) {
    return null;
  }

  const expression = `/users/user[username/text()='${credentials.username}' and passwordVerifier/text()='${credentials.passwordVerifier}']`;
  return directory.selectOne(expression);
}
