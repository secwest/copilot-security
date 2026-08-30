# Python cross-file dictionary key-isolation control

This topology-matched control passes the same hostile Flask value through the
same relative import and exact `dict.update` operation, but stores it only
under the unselected `audit` key. The fixed `preview` value is selected and
sent to the shell. Exact key-sensitive flow must not transfer taint between the
two dictionary values, and the witness must not create the temporary marker.
