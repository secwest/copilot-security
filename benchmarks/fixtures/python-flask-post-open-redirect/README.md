# Flask POST form open redirect

This fixture proves that prepending only `/` to a Flask `request.form` value
does not confine a POST redirect to the current origin. The route declares an
exact static POST method list. The witness disables redirect following and
performs no external request.
