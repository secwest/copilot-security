# Vulnerable Nodemailer raw-message access policy

An attacker-controlled raw message object and recipient cross three wrappers into a Nodemailer 9.0.0 transporter that explicitly disables file and URL access. The vulnerable raw-root path omits both policies, so `{ path }` file bytes or `{ href }` response bytes become the delivered message despite the deny configuration.
