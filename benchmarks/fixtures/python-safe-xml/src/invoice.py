from defusedxml.ElementTree import fromstring


def parse_invoice(request):
    if len(request.body) > 65536:
        raise ValueError("Invoice document is too large")
    root = fromstring(request.body)
    return {
        "customer": root.findtext("customer"),
        "amount": root.findtext("amount"),
    }
