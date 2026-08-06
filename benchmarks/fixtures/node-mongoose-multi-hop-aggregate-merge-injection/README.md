# Node Mongoose multi-hop aggregate merge injection

The complete JSON pipeline crosses three exact relative imports and becomes the pipeline passed to Mongoose `Model.aggregate()`. An attacker can combine `$set` with `$merge` to replace protected account state.
