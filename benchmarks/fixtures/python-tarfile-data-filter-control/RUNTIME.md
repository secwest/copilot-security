# Runtime evidence

- Python: 3.12.3
- Standard library: `tarfile`
- Extraction filter: `data`
- Resource limits: 32 members, 1 MiB per member, 2 MiB expanded total
- Entry policy: regular files and directories only; duplicate and
  case-colliding names rejected
- Witness boundary: one `../escaped-marker.txt` regular-file member
- Side effects: writes only inside a newly created temporary directory
- Network and shell access: none
- Resource witness: one bounded successful extraction and five fail-closed
  member, size, type, and name controls
