# Python cross-file server-side template injection

The Flask route passes caller-controlled Jinja template source through a
relative import. The wrapper evaluates that value with
`render_template_string`, allowing Jinja object traversal and server-side code
execution instead of treating the value as display data.
