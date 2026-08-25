from lxml import etree


def parse_document(document):
    parser = etree.ETCompatXMLParser()
    root = etree.fromstring(document, parser=parser)
    return list(root.itertext())
