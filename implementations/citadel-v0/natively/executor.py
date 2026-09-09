"""Executor: applies exactly two v0 actions.
  "info"      no-op (a granted, ledgered ping);
  "fs.write"  write params.content to ONE file under the scratch root, named by the
              resource host:<this node key>:scratch/<name>.
Anything else is refused.

Confinement is by descriptor, not by pathname: the scratch root is opened with
O_DIRECTORY|O_NOFOLLOW at the CONFIGURED path (never resolved, so a symlink put
there later is refused by the kernel) and its (dev, ino) must equal the identity
recorded when the root was created, the destination is lstat'ed relative to it and
refused if it is a symlink or anything but a regular file, the temp file is created
O_CREAT|O_EXCL|O_NOFOLLOW under a random name, and the rename is
descriptor-relative followed by an fsync of the directory. The write is atomic (temp
file + rename in the same directory), so a revocation that lands mid-flight never
leaves a half-applied file (spec section 6, executor exception). The temp descriptor
is owned by a file object from the moment it is opened (fdopen first, identity read
through the file object's fileno), so no exit path — the identity lookup failing
included — leaves a descriptor open: the file object closes it, the temp name is
unlinked relative to the directory descriptor, and the directory descriptor closes last.

Failure accounting is split at the rename: anything raised BEFORE os.replace is an
ordinary failure (no side effect exists; the temp file is removed). Anything raised
AFTER it — the directory fsync AND the close of the directory descriptor — is a
PostCommitError: the destination has already changed, so the node must ledger the
use as consumed. A close failure never masks a PostCommitError already propagating:
the original is kept and the close error is appended to its detail.

An exception FROM os.replace itself is decided by identity, never by the exception:
the temp file's (dev, ino) is taken from its open descriptor before the rename; if the
destination now carries that identity the rename took effect (PostCommitError, the
use consumed); if the temp file is still present under its own name and the
destination is not it, nothing was committed (the temp is removed, an ordinary
failure); anything else — neither lstat conclusive, the temp gone and the destination
not it — is an UNCERTAIN commit and fails closed as PostCommitError ("rename result
uncertain")."""

from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any

from .errors import PostCommitError, RefusedError

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_CONTENT = 64 * 1024
ACTIONS = ("info", "fs.write")
SCRATCH = ":scratch/"


def scratch_name_problem(name: str) -> str | None:
    """Why `name` is not a scratch name this executor can honour, or None: one path
    component of 1..64 characters from [A-Za-z0-9._-] starting with an alphanumeric,
    never `.` or `..` and never containing `..` — no separator, no dot segment, no
    whitespace. The ONE rule: the executor applies it at every write (`_name_for`),
    the grant verb at issue and the send verb at compose (before the node is built),
    and the grant document check at receive and at load (`grant.check_structure`), so
    a signed grant on file never names a resource nothing can serve (round-19 Fable
    read, C2: `grant --file ../seen.json` issued and stored)."""
    if not NAME_RE.fullmatch(name) or name in (".", "..") or ".." in name:
        return f"bad scratch name {name!r} (one component of [A-Za-z0-9._-], 1..64 characters)"
    return None


def scratch_name_of(resource: str) -> str | None:
    """The scratch name a `host:<key>:scratch/<name>` resource carries, else None."""
    _host, sep, name = resource.partition(SCRATCH)
    return name if sep else None


class Executor:
    def __init__(
        self, node_key: str, scratch_root: Path, root_identity: tuple[int, int] | None = None
    ):
        self.node_key = node_key
        self.scratch_root = Path(scratch_root)  # the configured path, deliberately unresolved
        # the node records the root's identity once at construction and hands the
        # same pair to every executor it builds; a bare Executor records its own
        self.root_identity = root_identity or self.create_root(self.scratch_root)

    @staticmethod
    def create_root(path: Path) -> tuple[int, int]:
        """Create the scratch root if it is missing and return its (dev, ino). The path
        is opened O_DIRECTORY|O_NOFOLLOW, so a symlink sitting at the configured path
        is refused here rather than followed (ValueError, like the key-dir checks)."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as e:
            raise ValueError(f"scratch root {path} is not a real directory: {e.strerror}") from e
        try:
            st = os.fstat(fd)
        finally:
            os.close(fd)
        return (st.st_dev, st.st_ino)

    def resource_for(self, name: str) -> str:
        return f"host:{self.node_key}:scratch/{name}"

    def _name_for(self, resource: str) -> str:
        prefix = f"host:{self.node_key}:scratch/"
        if not resource.startswith(prefix):
            raise RefusedError(
                "executor.resource", f"resource must be bound to this host as {prefix}<name>"
            )
        name = resource[len(prefix) :]
        why = scratch_name_problem(name)
        if why is not None:
            raise RefusedError("executor.resource.name", why)
        return name

    def apply(self, action: str, resource: str, params: dict[str, Any]) -> dict[str, Any]:
        if action == "info":
            return {"outcome": "applied", "note": "info: no-op"}
        if action == "fs.write":
            return self._fs_write(resource, params)
        raise RefusedError("executor.unsupported", f"action {action!r} is not one of {ACTIONS}")

    def _open_root(self) -> int:
        """A descriptor on the scratch root: the configured path opened without
        following a symlink, and the same (dev, ino) that was recorded at creation.
        Nothing is created here; a root that vanished is refused."""
        try:
            fd = os.open(self.scratch_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError as e:
            raise RefusedError("executor.scratch", "scratch root does not exist") from e
        except OSError as e:  # ELOOP: a symlink now sits at the path; ENOTDIR: a file does
            raise RefusedError(
                "executor.scratch", f"scratch root is not the real directory: {e.strerror}"
            ) from e
        try:
            fst = os.fstat(fd)
            if (fst.st_dev, fst.st_ino) != self.root_identity:
                raise RefusedError("executor.scratch", "scratch root changed underneath; refusing")
        except BaseException:
            os.close(fd)
            raise
        return fd

    @staticmethod
    def _check_destination(dirfd: int, name: str) -> None:
        try:
            st = os.lstat(name, dir_fd=dirfd)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise RefusedError("executor.resource.symlink", f"{name!r} is a symlink; refusing")
        if not stat.S_ISREG(st.st_mode):
            raise RefusedError("executor.resource.type", f"{name!r} is not a regular file")

    @staticmethod
    def _discard_tmp(dirfd: int, tmp: str) -> None:
        try:
            os.unlink(tmp, dir_fd=dirfd)
        except FileNotFoundError:
            pass

    @staticmethod
    def _post_commit(
        name: str, err: BaseException | None, close_error: BaseException | None = None
    ) -> PostCommitError:
        """The PostCommitError for a failure after the rename: the directory fsync
        error (kept as the cause), the close error, or both, the close error appended
        to the detail of whatever was already propagating."""
        if err is None:
            return PostCommitError(
                f"{name!r} was replaced but closing the directory descriptor failed: "
                f"{type(close_error).__name__}: {close_error}",
                close_error,
            )
        if isinstance(err, PostCommitError):
            base, cause = err.detail, err.cause
        else:
            base = (
                f"{name!r} was replaced but the directory fsync failed: {type(err).__name__}: {err}"
            )
            cause = err
        if close_error is not None:
            base += (
                f"; then closing the directory descriptor failed: "
                f"{type(close_error).__name__}: {close_error}"
            )
        return PostCommitError(base, cause)

    @staticmethod
    def _rename_outcome(dirfd: int, tmp: str, name: str, tmp_id: tuple[int, int]) -> str:
        """After os.replace raised: "committed" (the destination is the temp file),
        "uncommitted" (the temp file is still itself and the destination is not it)
        or "uncertain" (anything else). Decided by identity only."""

        def ident(n: str) -> tuple[int, int] | None | str:
            try:
                st = os.lstat(n, dir_fd=dirfd)
            except FileNotFoundError:
                return None
            except OSError:
                return "unreadable"
            return (st.st_dev, st.st_ino)

        dst = ident(name)
        if dst == tmp_id:
            return "committed"
        if dst == "unreadable":
            return "uncertain"
        src = ident(tmp)
        if src == tmp_id:
            return "uncommitted"
        return "uncertain"

    def _fs_write(self, resource: str, params: dict[str, Any]) -> dict[str, Any]:
        name = self._name_for(resource)
        content = params.get("content")
        if not isinstance(content, str):
            raise RefusedError("executor.params", "fs.write needs params.content (string)")
        data = content.encode("utf-8")
        if len(data) > MAX_CONTENT:
            raise RefusedError("executor.params", f"content over {MAX_CONTENT} bytes")
        if set(params) - {"content"}:
            raise RefusedError(
                "executor.params", f"unexpected params {sorted(set(params) - {'content'})}"
            )
        dirfd = self._open_root()
        committed = False  # True from the rename on: everything after it is committed state
        err: BaseException | None = None
        try:
            try:
                self._check_destination(dirfd, name)
                tmp = f".{name}.tmp-{secrets.token_hex(8)}"
                try:
                    fd = os.open(
                        tmp,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=dirfd,
                    )
                except FileExistsError as e:
                    raise RefusedError(
                        "executor.tmp_exists", f"temp name {tmp!r} already exists; refusing"
                    ) from e
                # ownership first: the file object owns the descriptor from here on,
                # so every failure path below closes it (the `with`); a failure of
                # fdopen itself, before ownership, closes the raw descriptor by hand
                try:
                    f = os.fdopen(fd, "wb")
                except BaseException:
                    try:
                        os.close(fd)
                    finally:
                        # the temp name goes whatever the close reported (a close
                        # that closes and then fails must not leave the name behind)
                        self._discard_tmp(dirfd, tmp)
                    raise
                try:
                    with f:
                        tst = os.fstat(f.fileno())
                        tmp_id = (tst.st_dev, tst.st_ino)  # the temp file's identity
                        f.write(data)
                        f.flush()
                        os.fsync(f.fileno())
                    self._check_destination(dirfd, name)  # re-check just before the rename
                except BaseException:
                    # nothing has changed at the destination: the descriptor is closed
                    # (the `with` above), the temp file is removed, and the caller sees
                    # an ordinary failure; the directory descriptor closes in `finally`
                    self._discard_tmp(dirfd, tmp)
                    raise
                try:
                    os.replace(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)  # the atomic step
                except Exception as re:  # noqa: BLE001 — classified by identity below
                    verdict = self._rename_outcome(dirfd, tmp, name, tmp_id)
                    if verdict == "uncommitted":
                        self._discard_tmp(dirfd, tmp)
                        raise
                    committed = True  # took effect, or fails closed as if it had
                    if verdict == "committed":
                        raise PostCommitError(
                            f"{name!r} was replaced but the rename reported failure: "
                            f"{type(re).__name__}: {re}",
                            re,
                        ) from re
                    raise PostCommitError(
                        f"rename result uncertain for {name!r} (neither the destination nor "
                        f"the temp file settles it); failing closed as committed: "
                        f"{type(re).__name__}: {re}",
                        re,
                    ) from re
                committed = True
                os.fsync(dirfd)  # the new directory entry itself, durable across power loss
            except Exception as e:  # noqa: BLE001 — classified below by `committed`
                err = e
        finally:
            # closing the root descriptor is part of the post-rename tail: a failure
            # here after the rename is committed-state territory too, and it must
            # never mask a failure that is already propagating
            try:
                os.close(dirfd)
            except Exception as ce:  # noqa: BLE001
                if committed:
                    err = self._post_commit(name, err, close_error=ce)
                elif err is None:
                    err = ce
        if err is not None:
            if committed and not isinstance(err, PostCommitError):
                err = self._post_commit(name, err)
            raise err from getattr(err, "cause", None)
        return {
            "outcome": "applied",
            "path": str(self.scratch_root / name),
            "bytes": len(data),
        }
