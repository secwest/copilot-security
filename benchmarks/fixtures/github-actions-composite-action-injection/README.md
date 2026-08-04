# Composite action script injection fixture

An externally controlled issue-comment body crosses a literal repository-local
composite-action call as the declared `release-name` input. The action inserts
that value into the JavaScript source generated for `actions/github-script`
while the caller supplies a release secret and write-capable token permissions.

The executable witness uses only a mock token and proves that expression
substitution turns the forwarded input into a second JavaScript statement.
