# Node Mongoose multi-hop safe aggregate append

The same request topology contributes one value only through exact `$eq` beneath a fixed appended `$match` field. A second appended stage fixes the public projection, and later `exec()` consumes the Aggregate.
