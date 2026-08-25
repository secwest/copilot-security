# Public CloudFormation administrator role

This fixture declares one `AWS::IAM::Role` whose conditionless trust policy
allows every AWS principal to call `sts:AssumeRole` and attaches the AWS-managed
`AdministratorAccess` policy without a permissions boundary. The benchmark
requires the scanner to preserve the complete same-role trust-to-authority path
before evaluating deployment, caller credentials, cross-account permission,
explicit denies, and concrete impact.
