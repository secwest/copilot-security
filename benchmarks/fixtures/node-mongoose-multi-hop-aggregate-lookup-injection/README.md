# Node Mongoose multi-hop aggregate lookup injection

The complete JSON pipeline crosses three exact relative imports and becomes the pipeline passed to Mongoose `Model.aggregate()`. An attacker can add `$lookup` and `$project` stages that expose a collection outside the intended account view.
