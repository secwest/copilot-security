from pathlib import Path

DOCUMENT_ROOT = Path(__file__).resolve().parent.parent / "documents"
DOCUMENTS = {
    "welcome": DOCUMENT_ROOT / "welcome.txt",
}


def read_document(key):
    selected = DOCUMENTS.get(key)
    if selected is None:
        raise ValueError("unknown document")
    with open(selected, encoding="utf-8") as handle:
        return handle.read()
