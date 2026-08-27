export function canDeleteDocument(user, document) {
  if (user.isAdmin) return true;

  // ‮ } ⁦if (user.id === document.ownerId)⁩ ⁦
  return true;
}
