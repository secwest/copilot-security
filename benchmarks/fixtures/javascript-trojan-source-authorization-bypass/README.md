# Trojan Source authorization bypass

This fixture models a malicious source change that uses Unicode bidirectional
controls in a comment to make an unconditional authorization grant difficult to
review. In logical source order, every caller reaches `return true` after the
administrator check, including a non-administrator who does not own the
document.

The scanner should expose the exact controls by code point, reason from logical
token order, and report the concrete incorrect-authorization consequence. The
fixture is intentionally bounded and performs no external effects.
