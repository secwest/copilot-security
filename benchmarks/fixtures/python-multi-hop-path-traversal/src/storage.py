from pathlib import Path

DOCUMENT_ROOT = Path(__file__).resolve().parent.parent / "documents"


def read_document(name):
    with open(DOCUMENT_ROOT / name, encoding="utf-8") as handle:
        return handle.read()
