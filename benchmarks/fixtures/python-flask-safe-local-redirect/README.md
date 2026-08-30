# Flask fixed-local redirect control

This control percent-encodes the same hostile query value beneath the fixed
local `/continue?next=` target. Its witness disables redirect following and
confirms that the Location cannot select another origin.
