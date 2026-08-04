# Reusable workflow script injection fixture

An externally controlled issue-comment body crosses a local reusable-workflow
call as the declared `release-name` string input. The called workflow inserts
that value into the JavaScript source generated for `actions/github-script`
while inheriting release secrets and write-capable permissions.

The executable witness uses only a mock token and proves that expression
substitution turns the forwarded data into JavaScript statements.
