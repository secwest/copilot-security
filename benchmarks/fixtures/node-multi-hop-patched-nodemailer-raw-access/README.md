# Patched Nodemailer raw-message access policy

This source-identical control upgrades only Nodemailer to 9.0.1. The repaired raw-root node receives both access policies and rejects `{ path }` and `{ href }` content with `EFILEACCESS` and `EURLACCESS` before message delivery.
