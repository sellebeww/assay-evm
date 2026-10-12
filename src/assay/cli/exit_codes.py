"""Process exit codes shared by all commands."""

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    NEGATIVE = 1
    USAGE = 2
    INCONCLUSIVE = 3
    INFRASTRUCTURE = 4
    INTEGRITY = 5
