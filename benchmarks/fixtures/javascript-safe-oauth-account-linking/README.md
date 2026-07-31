# Session-bound OAuth account-linking fixture

The application creates an unpredictable, one-time link transaction bound to
the authenticated browser session and local account. The callback consumes the
matching `state`, uses the transaction's S256 PKCE verifier, exchanges the code
at a fixed redirect URI, and links the verified external identity to the
transaction-bound account. A code and state initiated from an attacker session
cannot be completed from a victim session.
