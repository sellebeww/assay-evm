"""Pull request verification for continuous integration: `assay ci verify`.

The package holds the parts that do not run a sandbox: the diff of a pull request, the mapping of
`--fail-on` to an exit code and the Markdown summary. None of them uses a model or reads a secret.
"""
