# Safe Go shell-command control

This control retains the indexed request, wrapper, `CommandContext`, `sh -c`,
execution method, deterministic witness, and attack bytes. The request can only
select a complete server-owned command from an immutable map and cannot add
shell grammar.
