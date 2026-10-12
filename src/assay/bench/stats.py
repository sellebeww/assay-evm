"""Wilson score intervals and favorable-direction-free rounding of rates.

Percentages are never rounded in the favorable direction (bench/PROTOCOL.md, section 3): a rate
where lower is better rounds up, a rate where higher is better rounds down, and the bounds of an
interval round outward.
"""

import math
from typing import Final

Z95: Final = 1.959963984540054
_EPS: Final = 1e-9


def wilson(successes: int, total: int) -> tuple[float, float]:
    """The Wilson 95 percent interval of `successes` out of `total` (total must be positive)."""
    if total <= 0 or not 0 <= successes <= total:
        raise ValueError("wilson needs 0 <= successes <= total and total > 0")
    p = successes / total
    z2 = Z95 * Z95
    denominator = 1 + z2 / total
    centre = (p + z2 / (2 * total)) / denominator
    margin = Z95 * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _down(value: float) -> float:
    return math.floor(value * 1000 + _EPS) / 10


def _up(value: float) -> float:
    return math.ceil(value * 1000 - _EPS) / 10


def rate_text(successes: int, total: int, *, lower_is_better: bool) -> str:
    """`k/n (p %, 95 % CI lo to hi %)` with one decimal, or `n/a` for an empty sample."""
    if total == 0:
        return "n/a"
    low, high = wilson(successes, total)
    if lower_is_better:
        point = math.ceil(successes * 1000 / total) / 10
    else:
        point = math.floor(successes * 1000 / total) / 10
    return f"{successes}/{total} ({point:.1f} %, 95 % CI {_down(low):.1f} to {_up(high):.1f} %)"


def rate_json(successes: int, total: int) -> dict[str, object]:
    """The same numbers for `results.json`: counts and the unrounded interval bounds."""
    if total == 0:
        return {"count": successes, "of": total, "wilson95": None}
    low, high = wilson(successes, total)
    return {"count": successes, "of": total, "wilson95": [round(low, 6), round(high, 6)]}
