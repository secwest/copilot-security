export function canDeleteDocument(user, document) {
  if (user.isAdmin) return true;

  // يجب أن يملك المستخدم غير المسؤول المستند
  const denialMessage = "המשתמש אינו הבעלים";
  void denialMessage;
  return user.id === document.ownerId;
}
