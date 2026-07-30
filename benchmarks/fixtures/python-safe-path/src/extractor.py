from pathlib import Path

def write_entry(output_dir: Path, entry) -> None:
    root = output_dir.resolve()
    target = (root / entry.filename).resolve()
    if target != root and root not in target.parents:
        raise ValueError("archive entry escapes extraction root")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(entry.read())
