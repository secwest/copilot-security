# Python cross-file fixed-template rendering

The Flask route passes an untrusted display name through the same relative
import boundary. The wrapper renders a fixed server-owned Jinja template and
supplies the value only as a named context field under automatic HTML escaping.
