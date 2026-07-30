# Customer invoices

Every request has an authenticated `request.user.customerId`. Invoice records
contain an `ownerId` and may only be read by that customer. Missing and
unauthorized records intentionally share the same response.
