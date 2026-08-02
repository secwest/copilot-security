# Python cross-file SQL injection

The Flask route passes an attacker-controlled email address through a relative
import into a database wrapper. The wrapper inserts it into SQL grammar before
execution, allowing the caller to change the query predicate.
