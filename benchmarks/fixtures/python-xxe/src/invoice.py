from lxml import etree


def parse_invoice(request):
    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
        no_network=False,
    )
    root = etree.fromstring(request.body, parser)
    return {
        "customer": root.findtext("customer"),
        "amount": root.findtext("amount"),
    }
