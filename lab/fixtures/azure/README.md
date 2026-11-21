# AzureHound-format fixture

A hand-made AzureHound v1 payload (`meta.type: azure`, entries `{kind, data}`) with one VM, used by
`run-r-checks.sh` (R3). Findings it supports (docs/05-ce-compatibility.md): CE 9.7.1 ingests it,
and the `AZVM` objectid is the **full upper-cased ARM resource ID**, not the VM's GUID.
