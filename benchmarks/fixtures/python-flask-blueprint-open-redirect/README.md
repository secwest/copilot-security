# Flask registered-Blueprint open redirect

This Flask 3.1.3 fixture registers one official `Blueprint` on an official
application. The Blueprint route copies a query value behind only `/`, so a
value beginning with `/` produces a scheme-relative attacker-selected Location.
The witness inspects that header without following the redirect or using I/O.
