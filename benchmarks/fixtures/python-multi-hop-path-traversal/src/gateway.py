from .service import load_document


def route_document_read(name):
    return load_document(name)
