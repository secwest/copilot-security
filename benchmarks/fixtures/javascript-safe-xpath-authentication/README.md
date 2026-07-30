# Safe XPath authentication fixture

This service uses a fixed XPath expression and binds both bounded credential
strings as XPath variables. Quotes, boolean operators, path syntax, and
function text in either request value remain scalar data and cannot alter the
predicate AST or select a different account. `src/directory.js` provides the
same bounded XPath parser, administrator/viewer account data, boolean
precedence, node selection, and variable semantics as the vulnerable pair.
