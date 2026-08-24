# Patched node-tar decompression control

This source-identical negative control changes only `tar` from 7.5.18 to
7.5.19. The repaired parser defaults `maxDecompressionRatio` to 1000 and aborts
compressed archive processing when cumulative decompressed output crosses that
ratio.

The shared bounded witness verifies the guard without extracting its payload.
