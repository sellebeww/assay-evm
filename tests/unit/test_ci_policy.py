"""`--fail-on` and the exit code of `assay ci verify`."""

import pytest

from assay.ci.policy import DEFAULT_FAIL_ON, FailOn, exit_code
from assay.cli.exit_codes import ExitCode

OK, NEG, USAGE, INCONCLUSIVE, INFRA, INTEGRITY = (
    ExitCode.SUCCESS,
    ExitCode.NEGATIVE,
    ExitCode.USAGE,
    ExitCode.INCONCLUSIVE,
    ExitCode.INFRASTRUCTURE,
    ExitCode.INTEGRITY,
)


@pytest.mark.parametrize(
    ("fail_on", "results", "expected"),
    [
        (FailOn.REJECTED, [OK], OK),
        (FailOn.REJECTED, [], OK),
        (FailOn.REJECTED, [NEG], NEG),
        (FailOn.REJECTED, [INCONCLUSIVE], OK),
        (FailOn.REJECTED, [OK, INCONCLUSIVE, NEG], NEG),
        (FailOn.REJECTED, [INTEGRITY], INTEGRITY),
        (FailOn.INCONCLUSIVE, [OK], OK),
        (FailOn.INCONCLUSIVE, [INCONCLUSIVE], INCONCLUSIVE),
        (FailOn.INCONCLUSIVE, [OK, INCONCLUSIVE], INCONCLUSIVE),
        (FailOn.INCONCLUSIVE, [INCONCLUSIVE, NEG], NEG),
        (FailOn.INCONCLUSIVE, [NEG, INTEGRITY], INTEGRITY),
        (FailOn.NEVER, [NEG], OK),
        (FailOn.NEVER, [INCONCLUSIVE, NEG, INTEGRITY], OK),
        (FailOn.NEVER, [OK], OK),
    ],
)
def test_verdicts_follow_the_policy(
    fail_on: FailOn, results: list[ExitCode], expected: ExitCode
) -> None:
    assert exit_code(results, fail_on) is expected


@pytest.mark.parametrize("fail_on", list(FailOn))
def test_usage_and_infrastructure_problems_fail_under_every_policy(fail_on: FailOn) -> None:
    assert exit_code([OK, USAGE], fail_on) is USAGE
    assert exit_code([NEG, INFRA, INTEGRITY], fail_on) is INFRA
    assert exit_code([INFRA, USAGE], fail_on) is USAGE


def test_default_treats_an_unknown_result_as_a_failure() -> None:
    assert DEFAULT_FAIL_ON is FailOn.INCONCLUSIVE
    assert exit_code([INCONCLUSIVE], DEFAULT_FAIL_ON) is INCONCLUSIVE
