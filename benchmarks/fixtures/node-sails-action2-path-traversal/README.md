# Sails Action2 declared-input path traversal

The Action2 controller declares `filename`, then uses that request input in an
exact `node:fs` path sink. The bounded witness reads only the checked-in victim
marker outside the thumbnail directory and performs no write or network action.
