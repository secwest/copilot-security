import json


def import_preferences(request):
    if len(request.body) > 4096:
        raise ValueError("Preference document is too large")
    payload = json.loads(request.body.decode("utf-8"))
    if not isinstance(payload, dict) or set(payload) - {"theme", "locale"}:
        raise ValueError("Unexpected preference fields")
    return {
        "theme": str(payload.get("theme", "system")),
        "locale": str(payload.get("locale", "en")),
    }
