# Django root-prefix open redirect

This fixture proves that prepending only `/` to a Django query value does not
confine the redirect to the current origin. A value beginning with `/` yields a
scheme-relative `//attacker.invalid/...` Location. The witness disables redirect
following and performs no external request.
