last_effect = None


def mark(value):
    global last_effect
    last_effect = value
    return {"effect": value}
