"""Errors raised by the ledger."""


class LedgerError(Exception):
    """A ledger operation was refused or could not complete."""


class InvalidInput(LedgerError, ValueError):
    """An argument does not pass validation."""


class NotFound(LedgerError):
    """A referenced row does not exist."""


class SchemaVersionError(LedgerError):
    """The database is not a ledger, or its schema version is not supported."""


class LedgerIntegrityError(LedgerError):
    """The database itself rejected a change (constraint or trigger)."""


class IllegalTransition(LedgerError):
    """A finding transition is not in the lifecycle table or lacks its evidence."""


class ClaimPromotionError(LedgerError):
    """A claim cannot take the status that the oracle run's verdict would give it."""


class BlobError(LedgerError):
    """A blob could not be stored or read."""


class BlobCorrupted(BlobError):
    """A stored blob no longer matches its sha256."""
