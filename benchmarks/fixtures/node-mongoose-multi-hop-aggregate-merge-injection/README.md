# Node Mongoose multi-hop aggregate merge injection

An attacker-controlled JSON stage array crosses three exact relative imports and is spread before a fixed `$merge` stage in Mongoose `Model.aggregate()`. The fixed destination does not make attacker-selected `$set` stages safe: they can replace protected account state before the write.
