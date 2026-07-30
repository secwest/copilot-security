# Customer invoices

Every request has an authenticated `request.user.customerId`. Invoice records
contain an `ownerId` and may only be read by that customer. Invoice identifiers
are public UUIDs that can appear in emails and support tickets.
