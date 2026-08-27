<?php

declare(strict_types=1);

function findUsers(PDO $database): array
{
    $email = $_GET["email"] ?? "";
    $query = "SELECT id, email, role FROM users WHERE email = ?";
    $statement = $database->prepare($query);
    $statement->execute([$email]);

    return $statement->fetchAll(PDO::FETCH_ASSOC);
}
