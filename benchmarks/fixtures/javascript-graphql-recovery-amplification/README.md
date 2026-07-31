# GraphQL recovery-operation amplification fixture

The HTTP gateway applies a three-request client limit before executing a parsed
GraphQL document, but one document may contain an unbounded number of aliased
`verifyRecoveryCode` mutations. The recovery resolver has no account-scoped
attempt budget. An unauthenticated attacker can therefore submit four guesses
as aliases in one allowed request, obtain the reset capability from the fourth
resolver invocation, and use it to replace the victim's password even though a
fourth ordinary HTTP request would be rejected.
