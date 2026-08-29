# Sails Action2 relative-wrapper path traversal

An explicitly routed Action2 passes its declared `filename` input through one
relative module call into an exact Node filesystem path sink. The witness reads
only a checked-in inert marker and performs no write or network operation.
