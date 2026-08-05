# Go transaction function-value object deletion

The DELETE route aliases imported transaction factory and finalizer functions
before calling them. Both imported helpers also alias their leaf functions.
The leaf opens and commits the real `database/sql` transaction. The offline
driver proves that an attacker can make a victim invoice deletion durable
without principal scope through the complete function-value path.
