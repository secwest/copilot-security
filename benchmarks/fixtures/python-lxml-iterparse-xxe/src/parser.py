from lxml import etree


def parse_events(document):
    events = list(etree.iterparse(document, events=("end",)))
    return [element.text for _, element in events]
