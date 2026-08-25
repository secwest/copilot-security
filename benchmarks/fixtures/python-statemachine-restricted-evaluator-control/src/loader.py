from __future__ import annotations

from statemachine.io.scxml.processor import SCXMLProcessor


def run_statechart(document: str):
    processor = SCXMLProcessor()
    processor.parse_scxml("uploaded", document)
    machine = processor.start()
    return machine.model.result
