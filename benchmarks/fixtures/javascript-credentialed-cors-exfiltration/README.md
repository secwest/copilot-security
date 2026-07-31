# Credentialed CORS secret exfiltration

The API reflects every request `Origin` into
`Access-Control-Allow-Origin` while also enabling credentialed cross-origin
reads. A script on an attacker-controlled same-site subdomain can therefore
send the victim's session cookie, read the protected API-key response, and use
the disclosed key outside the victim browser.
