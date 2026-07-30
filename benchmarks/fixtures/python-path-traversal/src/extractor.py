from pathlib import Path

def write_entry(output_dir: Path, entry) -> None:
    target = output_dir / entry.filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(entry.read())
