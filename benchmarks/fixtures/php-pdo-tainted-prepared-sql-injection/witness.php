<?php

declare(strict_types=1);

require __DIR__ . "/src/search.php";

$database = new PDO("sqlite::memory:");
$database->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$database->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, role TEXT)");
$database->exec("INSERT INTO users (email, role) VALUES ('admin@example.test', 'admin')");
$database->exec("INSERT INTO users (email, role) VALUES ('user@example.test', 'user')");

$_GET["email"] = "' OR 1=1 -- ";
$rows = findUsers($database);
if (count($rows) !== 2) {
    fwrite(STDERR, "expected injected predicate to return both rows\n");
    exit(1);
}

echo "injected_rows=2\n";
