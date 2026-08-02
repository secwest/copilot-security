# Cross-file fixed-template rendering

The route passes an untrusted display name across the same relative-import
boundary. The wrapper renders a fixed server-owned Pug template and supplies
the value only through an explicitly constructed data object, where Pug's
escaped interpolation treats it as text rather than template grammar.
