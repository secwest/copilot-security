# Patched jsonpath-plus expression flow

This is the matched negative for the 10.3.0 expression-injection fixture. The
HTTP source, three wrappers, static JSON document, and official API call are
identical, but jsonpath-plus 10.4.0 blocks the accessor lookup bypass and the
recovered `Function` constructor in its safe evaluator.
