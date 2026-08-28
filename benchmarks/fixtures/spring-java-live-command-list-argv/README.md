# Spring Java live command-list argv control

This topology-matched control starts with the same benign `ProcessBuilder`,
obtains and aliases the live list returned by `ProcessBuilder.command()`, and
rebuilds that list before `start()`. It keeps `printf` fixed and passes the
request value as one ordinary operating-system argument, so shell
metacharacters remain data.
