# Python cross-file command injection

The Flask route reads an attacker-controlled report name and passes it through
a relative import into a shell-command wrapper. The wrapper interpolates the
value into the command interpreted by `/bin/sh`, allowing command injection.
