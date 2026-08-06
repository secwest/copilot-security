# Node Mongoose multi-hop bulk replacement mass assignment

The complete JSON document crosses three exact relative imports and becomes a `replaceOne.replacement` document in `bulkWrite()`. The attacker can overwrite protected role and MFA fields.
