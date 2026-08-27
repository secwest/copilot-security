# Natural bidirectional-language control

This negative control implements the same administrator-or-owner policy without
explicit Unicode direction controls. Arabic and Hebrew text appears only as
ordinary prose. A non-administrator who does not own the document is denied.

The scanner should not equate right-to-left language text with a source-spoofing
vulnerability and should not report an authorization bypass.
