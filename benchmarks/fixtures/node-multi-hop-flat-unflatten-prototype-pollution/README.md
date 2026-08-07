# Vulnerable flat.unflatten flow

An Express JSON object crosses three relative-import wrapper boundaries into
the official `flat.unflatten(original)` API under an exact vulnerable 4.1.0
runtime pin. A parser-produced own key such as `__proto__.isAdmin` is split on
the delimiter, follows `Object.prototype`, and gives fresh objects inherited
authorization state. This published vulnerable release is omitted by the
reviewed advisory's machine-readable 4.x range.
