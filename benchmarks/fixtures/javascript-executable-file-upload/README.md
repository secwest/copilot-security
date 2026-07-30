# Executable extension upload

The public extension-upload route retains both the attacking filename and bytes
and writes them directly into the application's extension directory. A separate
startup component imports every `.mjs` file from that directory and invokes its
activation hook.

An attacking client can therefore upload a JavaScript module and have it execute
with the application's privileges during the next extension activation pass.
