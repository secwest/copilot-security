export function requireDirectoryAdministrator(directory, session) {
  if (!session?.authenticated || typeof session.directorySubject !== "string") {
    return null;
  }

  const filter = `(&(member=${session.directorySubject})(cn=administrators))`;
  return directory.searchOne(filter);
}
