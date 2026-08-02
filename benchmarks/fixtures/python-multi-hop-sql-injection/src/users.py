import sqlite3

connection = sqlite3.connect("users.db")


def find_user(email):
    cursor = connection.cursor()
    return cursor.execute(f"SELECT id FROM users WHERE email = '{email}'").fetchone()
