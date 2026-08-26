# Pickem terminal control-sequence injection

This affected fixture maps remote release titles and descriptions into the
display fields consumed by the official `pickem` 1.0.6 terminal picker.

The witness never opens a TTY and never emits its rendered string. It invokes
the public `createFormatter`, inspects the returned bytes, and prints only
booleans plus the unchanged inert selected value. The marker contains no
command. Version 1.0.6 retains OSC, BEL, DEL, C1, and the inert clipboard
marker; the paired 1.0.7 control removes them.
