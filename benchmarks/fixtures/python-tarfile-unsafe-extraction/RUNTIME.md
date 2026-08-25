# Runtime evidence

- Python: 3.12.3
- Standard library: `tarfile`
- Extraction filter: omitted (`fully_trusted` behavior before Python 3.14)
- Witness boundary: one `../escaped-marker.txt` regular-file member
- Side effects: writes only inside a newly created temporary directory
- Network and shell access: none
