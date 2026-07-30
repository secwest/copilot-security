# Hostname formatting service

The HTTP route is reachable by unauthenticated users. Hostnames are restricted
to DNS syntax and passed as data to a fixed `printf` format string without a
command shell.
