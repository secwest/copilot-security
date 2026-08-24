# Repaired Sequelize Oracle query fixture

This control is source-identical to the vulnerable fixture except for its exact Sequelize 6.37.4 dependency. The repaired Oracle escape path accepts only exact package-generated `TO_TIMESTAMP_TZ(value, format)` and `TO_DATE(value, format)` strings, validates their values and formats, and rejects trailing attacker-controlled syntax.

`npm run witness` exercises the installed package's real Oracle query generator with a minimal inert dialect-module substitute. It opens no listener, loads no native Oracle driver, contacts no database or network service, and changes no data. The identical bounded payload must fail with `Invalid SQL function call.` before a query can execute.
