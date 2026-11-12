# Assay

Assay checks whether a patch for a Solidity vulnerability actually closes it, or only passes the
tests that already existed.

A patch that makes the test suite pass is not necessarily a fix. It can stop the exact exploit
that was reported and leave a close variant open. It can switch off the behavior the contract
exists for. It can change storage layout, ABI or events so that deployed state or integrations
break. Assay runs the exploit, a bounded search for variants, the benign tests and an interface
comparison against the patched code, in a sandbox, and says which of those cases it found.

<div class="grid cards" markdown>

- **[Quickstart](quickstart.md)**: install, build the runner image, verify a patch.
- **[Concepts](concepts.md)**: oracles, verdicts, evidence levels and bounds.
- **[Case studies](case-studies.md)**: four patches of one fixture, and what Assay says about each.
- **[GitHub Action](github-action.md)**: verify the Solidity changes of every pull request.
- **[Reference](cli.md)**: commands, exit codes, JSON schemas and SARIF.
- **[Report viewer](viewer.md)**: open a JSON report in the browser.

</div>

## What a verdict means

`VERIFIED_WITHIN_BOUNDS` means that every required oracle passed and that no variant of the exploit
was found within the bounds that ran. **It is not a proof that the patch is correct or that the code
is free of vulnerabilities.** The bounds are printed with every verdict and recorded in the
evidence bundle. Read [the limitations](limitations.md) before relying on a result.
