"""How the exit code of `assay ci verify` follows from the results and from `--fail-on`."""

from collections.abc import Iterable
from enum import StrEnum
from typing import Final

from assay.cli.exit_codes import ExitCode


class FailOn(StrEnum):
    """Which results make the command fail.

    `rejected` fails on a REJECTED verdict and on an integrity violation. `inconclusive` also
    fails on an INCONCLUSIVE verdict, so that an unknown result is never taken for a pass.
    `never` reports without failing on a verdict.
    """

    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    NEVER = "never"


DEFAULT_FAIL_ON: Final = FailOn.INCONCLUSIVE

# A problem of the command line (2) or of the infrastructure (4) means that no verdict exists, so
# it fails under every policy. The remaining codes are verdicts.
_ALWAYS: Final = (ExitCode.USAGE, ExitCode.INFRASTRUCTURE)
_VERDICTS: Final = {
    FailOn.REJECTED: (ExitCode.INTEGRITY, ExitCode.NEGATIVE),
    FailOn.INCONCLUSIVE: (ExitCode.INTEGRITY, ExitCode.NEGATIVE, ExitCode.INCONCLUSIVE),
    FailOn.NEVER: (),
}
_PRIORITY: Final = (
    ExitCode.USAGE,
    ExitCode.INFRASTRUCTURE,
    ExitCode.INTEGRITY,
    ExitCode.NEGATIVE,
    ExitCode.INCONCLUSIVE,
)


def exit_code(results: Iterable[ExitCode], fail_on: FailOn) -> ExitCode:
    """The exit code for the per-PoC codes `results` under the policy `fail_on`.

    Of the codes that fail under the policy, the most serious one wins: usage, infrastructure,
    integrity violation, REJECTED, INCONCLUSIVE. Without one the exit code is 0.
    """
    failing = {*_ALWAYS, *_VERDICTS[fail_on]}
    present = {code for code in results if code in failing}
    for code in _PRIORITY:
        if code in present:
            return code
    return ExitCode.SUCCESS
