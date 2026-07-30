# Canonical profile-data upload

This control keeps user profile data outside the application's extension
directory. It accepts only bounded JSON, validates an exact data model, and
writes a canonical serialization under a server-generated `.json` name.

The unchanged extension loader can import only separately provisioned `.mjs`
files from the extension directory; uploaded bytes never reach that root.
