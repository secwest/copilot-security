# Password-reset link origin poisoning

The public reset endpoint issues a strong, expiring, one-time token whose store
keeps at most one live record per account, but builds the emailed absolute URL
from `X-Forwarded-Host` or `Host`. An attacker can
request a reset for a victim with an attacker-controlled forwarded host. If the
victim follows the legitimate email, the reset token is sent to the attacker's
origin and can then be redeemed at the real application to change the victim's
password.
