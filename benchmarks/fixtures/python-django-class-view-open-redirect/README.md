# Django class-view root-prefix open redirect

This fixture registers a direct `django.views.View` subclass through
`ContinueView.as_view()`. Its `get(self, request)` handler prepends only `/` to
an attacker-selected query value, producing a scheme-relative
`//attacker.invalid/...` Location. The witness disables redirect following and
performs no external request.
