# Specific CloudFormation administrator role control

This source-identical control grants the administrator role only to one exact
AWS account principal. An intentionally privileged role with a specific trust
boundary must not be reported as a conditionless public-principal role.
