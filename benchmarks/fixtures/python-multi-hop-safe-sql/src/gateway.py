from .service import lookup_user


def route_user_lookup(email):
    return lookup_user(
        email,
    )
