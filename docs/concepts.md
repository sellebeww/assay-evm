# Concepts

## The question

Assay answers one question about a patch: does it close the exploit, within recorded bounds,
without breaking what the contract is for? It judges patches. It does not look for new bugs.

## Oracles

A verdict comes from five deterministic oracles, run in order, and optionally a sixth.

| Oracle | Question |
|---|---|
| integrity | Did the patch stay in scope and leave tests, the PoC and configuration alone? |
| exploit | Does the PoC work on the original code and stop working on the patched code? |
| variant | Does a bounded fuzzing and invariant search find a close variant of the exploit on the patched code? A variant counts only after a generated test reproduced it three times. |
| behavior | Do the benign tests still pass with the same recorded results? |
| regression | Are storage layout, ABI and events free of breaking changes? |
| symbolic (optional) | Does Halmos find no counterexample within stated loop and calldata bounds? |

No model takes part in a verdict. A model can propose a PoC or a patch, but only the oracles
change a status, and a timeout or an unknown result is never reported as a pass.

## Verdicts and exit codes

| Verdict | Exit code | Meaning |
|---|---|---|
| `VERIFIED_WITHIN_BOUNDS` | 0 | All required oracles passed; nothing was found within the bounds. |
| `REJECTED` | 1 | At least one oracle failed. |
| `INCONCLUSIVE` | 3 | None failed, but one was inconclusive or did not run. |

Usage errors exit 2, infrastructure problems (Docker, image, memory) 4, integrity violations 5.

## Evidence levels

| Level | Meaning |
|---|---|
| E0 | Unverified signal (static analyzer output or a hypothesis). |
| E1 | Exploit reproduced on the original revision. |
| E2 | The patch blocks the PoC without a detected regression; the variant search did not decide. |
| E3 | All required oracles passed within the recorded bounds. |

## Bounds

Every verdict is printed with the bounds that ran: seeds, runs, depth, time, and symbolic loop and
calldata limits. A bounded search cannot show that no variant exists, so a verdict is valid within
those numbers only.

## Evidence bundles

`--bundle-out` writes the inputs, the evidence and a manifest with a sha256 for every file.
`assay replay` re-checks a bundle offline and compares the verdicts with the manifest. A bundle is
tamper-evident, not signed.

More: [oracles](oracles.md), [design](design.md), [threat model](threat-model.md).
