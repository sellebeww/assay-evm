"""Stand-in for the `solc_select` package in the runner image (ADR 0015).

crytic-compile imports `solc_select.solc_select` when it is loaded, but calls it only to look up
or download a compiler by version. The runner image has exactly one compiler, the solc pinned in
`versions.lock`, and no network, so this module reports no installed versions and refuses every
installation instead of downloading anything.
"""
