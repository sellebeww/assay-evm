# SARIF 2.1.0 schema

`sarif-schema-2.1.0.json` is an unmodified copy of the official JSON schema of the Static Analysis
Results Interchange Format (SARIF) version 2.1.0, published by OASIS with the errata 01 OASIS
Standard:

- Source: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json>
- Specification: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html>
- sha256 of the copy: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`

The schema is a JSON Schema draft-04 document. The unit tests of the SARIF export
(`tests/unit/test_sarif.py`) validate every document that `assay scan --format sarif` produces
against it, so the tests need no network access. The copy is test material only and is not part
of the installed package. The specification and its schema are subject to the OASIS
intellectual property policy; see the specification for its notices.
