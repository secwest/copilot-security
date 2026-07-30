# Payout approval

Customers can edit a pending payout through `updates.py` while separately
requesting approval through `payouts.py`. Approval locks and transitions the
record atomically, then sends the exact validated snapshot.
