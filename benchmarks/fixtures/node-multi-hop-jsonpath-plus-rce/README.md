# Vulnerable jsonpath-plus expression flow

An Express query-string JSONPath crosses three relative-import wrapper
boundaries into the official `JSONPath({ path, json })` API under an exact
10.3.0 runtime pin. The package's nominally safe evaluator still exposes
`__lookupGetter__`, which recovers a function constructor and executes a
host-process expression. Version 10.4.0 blocks the accessor lookup bypass and
rejects the recovered `Function` constructor.
