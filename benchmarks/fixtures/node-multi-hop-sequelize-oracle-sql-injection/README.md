# Reachable Sequelize Oracle SQL injection fixture

An Express query value crosses three relative-import wrappers before it becomes a `where` value in a model created by an Oracle-configured Sequelize 6.37.3 instance. That release returns strings beginning with `TO_TIMESTAMP` or `TO_DATE` without quote escaping, so the remaining text can change the generated predicate.

`npm run witness` exercises the installed package's real Oracle query generator with a minimal inert dialect-module substitute. It opens no listener, loads no native Oracle driver, contacts no database or network service, changes no data, and expects only the generated SQL text. The affected build emits the bounded `OR 1=1--` predicate; the repaired twin rejects the identical value before any query can execute.
