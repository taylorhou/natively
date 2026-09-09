"""Error types. Every verification failure is a VerifyError with a stable `reason`
code that the node prints and ledgers (spec principle 5: shown, never swallowed)."""


class NativelyError(Exception):
    """Base class for library errors."""


class VerifyError(NativelyError):
    """A signature, scope, freshness, or structure check failed.

    `reason` is a short machine code (e.g. "grant.expired"); `detail` is prose.
    """

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class RefusedError(NativelyError):
    """The executor refused an action (out of scope, unsupported, denied)."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class PostCommitError(NativelyError):
    """The executor failed AFTER its side effect existed (the rename landed, then a
    later step such as the directory fsync raised). The action may well have taken
    effect, so the node ledgers it with a use-consuming outcome; never an ordinary
    `failed`, which consumes nothing."""

    def __init__(self, detail: str, cause: BaseException | None = None):
        self.detail = detail
        self.cause = cause
        super().__init__(detail)


class StorageError(NativelyError):
    """A LOCAL storage write failed while a bundle was being applied (the feed, the
    ledger, a state file). Not hostile input: nothing about the bundle is known to be
    wrong, so it is not ledgered as malformed. The adapter leaves the mail unseen
    (re-read next poll) and neither the cursor nor the freshness clock moves."""

    def __init__(self, detail: str, cause: BaseException | None = None):
        self.detail = detail
        self.cause = cause
        super().__init__(detail)


class IntegrityError(StorageError):
    """A LOCAL file this node wrote is not well formed (a torn tail after power loss,
    a line that does not parse). Local corruption, never peer input: it is a storage
    failure like any other (nothing ledgered as malformed, the mail stays unseen)
    until the operator repairs the file (`natively feed repair`)."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)
