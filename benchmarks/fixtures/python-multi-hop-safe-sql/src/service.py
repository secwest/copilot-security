from .users import find_user


def lookup_user(email):
    return find_user(
        email,
    )
