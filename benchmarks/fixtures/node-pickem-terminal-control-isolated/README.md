# Pickem terminal control isolated

This repaired fixture is application-source and witness identical to the
affected pair and changes only the production dependency to `pickem` 1.0.7.
That release applies `sanitizeDisplay` at terminal render boundaries, so the
non-interactive witness observes no OSC, BEL, DEL, C1, or clipboard marker and
still returns the same inert item value.
