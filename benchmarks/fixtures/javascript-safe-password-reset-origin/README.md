# Fixed-origin password-reset links

The public endpoint uses the same strong, expiring, one-time token workflow as
the vulnerable control and keeps at most one live token record per account.
Reset URLs are resolved only against a deployment configuration constant.
Request `Host`, `X-Forwarded-Host`, and protocol headers cannot influence the
emailed origin, so following the legitimate message does not disclose the token
to an attacker-controlled site.
