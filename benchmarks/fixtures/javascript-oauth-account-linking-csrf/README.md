# OAuth account-linking CSRF fixture

The application starts and completes an OAuth authorization-code flow without a
server-generated `state` value, browser-session transaction binding, or PKCE.
An attacker can obtain a code for their own external identity and make a victim
submit it while authenticated. The callback links the attacker's external
identity to the victim's local account, so the attacker can subsequently sign
in as the victim.
