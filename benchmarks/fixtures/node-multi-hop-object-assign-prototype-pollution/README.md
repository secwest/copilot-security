# Multi-hop Object.assign prototype replacement

An Express JSON object crosses three relative-import wrappers into a source position of the built-in `Object.assign()`. Its own `__proto__` property invokes the ordinary target's inherited setter and replaces that target's prototype with attacker-selected authorization state.
