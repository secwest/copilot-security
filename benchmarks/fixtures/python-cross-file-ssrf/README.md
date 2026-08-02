# Python cross-file server-side request forgery

The Flask route passes a caller-controlled absolute URL through a relative
import into a `requests` wrapper. The wrapper follows redirects, reaches the
attacker-selected destination from the application network, and returns a
strictly time- and size-bounded response body.
