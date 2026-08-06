from .service import load_document


def route_document_read(key):
    return load_document(key)
