# Vulnerable js-yaml flow-pair parsing

An HTTP request body crosses three relative-import wrappers before `js-yaml` 5.2.1 parses it. Nested flow-sequence pair keys can make the synchronous parser reparse each nested key twice, producing exponential CPU work from a payload under 200 bytes and blocking the Node.js event loop.

The dependency-free witness isolates the vulnerable reparse recurrence with a bounded operation counter so the benchmark proves exponential growth without hanging the test runner.
