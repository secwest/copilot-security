# Spring Java fluent ProcessBuilder injection fixture

This deliberately vulnerable Spring MVC handler passes a request parameter to
the command-string operand after `/bin/bash -l -c` in a fluent, unassigned
`ProcessBuilder` chain. The executable regression uses only the fixed string
`printf spring-java-witness`; it performs no file, network, credential,
persistence, or privilege operation.

The paired `spring-java-fluent-process-builder-argv` fixture keeps the same
handler and fluent builder topology but passes request data as one ordinary
argument to `printf`.
