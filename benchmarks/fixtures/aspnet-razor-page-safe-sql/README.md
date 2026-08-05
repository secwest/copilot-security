# Safe Razor Page handler SQL fixture

This control keeps the same Razor Page handler and typed service topology as
the vulnerable pair. The SQL text is fixed and the remotely bound `filter`
value is carried only by a typed `SqlParameter`, so no SQL-injection finding is
expected.
