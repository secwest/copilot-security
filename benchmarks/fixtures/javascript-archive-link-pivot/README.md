# Archive link-pivot fixture

The importer lexically contains every archive member name beneath its staging
root, but materializes symbolic and hard links without validating their link
targets. A later regular member can therefore write through an earlier link and
replace trusted service configuration outside the extraction root even though
both member names themselves pass containment checks.
