"""Ed25519 key handling. Private keys live ONLY under the keys directory
(default ~/.config/citadel-mayor/natively/), mode 0600, never under city assets
and never in a wire body. Public keys are 'ed25519:<base64 raw 32 bytes>'."""

from __future__ import annotations

import base64
import os
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import VerifyError

DEFAULT_KEYS_DIR = Path("~/.config/citadel-mayor/natively").expanduser()
# the tool directory (natively/, state/, scratch/ live here; keys never do)
PACKAGE_DIR = Path(__file__).resolve().parents[1]
# the code itself (this package's modules): the executor's root never is or holds it
CODE_DIR = Path(__file__).resolve().parent
PREFIX = "ed25519:"
ROLES = ("host", "agent", "principal-standin")
ALIAS = " (names that differ only by case or Unicode normalization count as one name)"


def _fold(component: str) -> str:
    """One path component of an unresolved remainder as the filesystem might name it:
    Unicode's own canonical caseless match, `NFD(casefold(NFD(x)))` (Unicode 15
    §3.13, D145), on every filesystem. Conservative by design: two absent names that
    differ only by case or by Unicode normalization are ONE name to the separation
    checks even where the filesystem would keep them apart — the operator picks
    distinct names. Before, the remainder was compared literally, and on this
    case-insensitive filesystem two absent siblings `state` and `STATE` passed, the
    node created the state directory and admitted its alias as the executor's root
    (round-19 gate R1; Fable A: NFC/NFD pairs, and aliases one level down or up).

    Why D145's formula and not NFC around the fold: with NFC first, U+1FB7 (alpha
    with perispomeni and ypogegrammeni) and its uppercase spelling U+0391 U+0342
    U+0345 fold to two different strings — NFC recomposes the capital with the
    iota subscript across the perispomeni into U+1FBC, whose full fold turns the
    subscript into a BASE iota that the perispomeni then attaches to — while APFS
    treats the two as one name, so the node constructed with the executor's root
    equal to the state directory (round-20 Fable read, N1; U+1FC7 and U+1FF7 the
    same). Decomposed first, both spellings fold to U+03B1 U+0342 U+03B9. The fold
    can only see the case pairs the interpreter's Unicode tables know (14.0 on
    this Python; this kernel folds pairs Unicode 15 and 16 added, N2), so the
    post-creation identity re-check `check_scratch_identity` stands behind it."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", component).casefold())


def _identity(p: Path) -> tuple[tuple[tuple[int, int], ...], tuple[str, ...]]:
    """The filesystem identity of `p`: the (device, inode) of every existing ancestor
    from the root down to the deepest existing prefix, then the remainder below it
    with every component folded (`_fold`). Two names for one directory — through a
    symlink, or a case alias on a case-insensitive filesystem (`../NATIVELY/state`
    beside `state`) — have one identity; a lexical compare of resolved paths does
    not see the alias, and a scratch root that IS the state directory passed
    (round-19 self-gate, third run)."""
    parts = Path(p).expanduser().resolve().parts
    chain: list[tuple[int, int]] = []
    for k in range(1, len(parts) + 1):
        try:
            st = Path(*parts[:k]).stat()
        except OSError:
            return tuple(chain), tuple(_fold(x) for x in parts[k - 1 :])
        chain.append((st.st_dev, st.st_ino))
    return tuple(chain), ()


def _same(a: Path, b: Path) -> bool:
    return _identity(a) == _identity(b)


def _within(inner: Path, outer: Path) -> bool:
    """`inner` lies strictly inside `outer`, by filesystem identity where the paths
    exist and by their folded remainders below the deepest existing prefix."""
    ic, ir = _identity(inner)
    oc, orest = _identity(outer)
    if not orest:  # outer exists in full
        return ic[: len(oc)] == oc and (len(ic) > len(oc) or bool(ir))
    return ic == oc and len(ir) > len(orest) and ir[: len(orest)] == orest


def check_scratch_separation(scratch_dir: Path, *, state_dir: Path) -> Path:
    """The executor's root (the scratch directory) must not be, sit inside, or
    contain the state directory or the code directory, symlinks resolved; inside
    the tool directory it may only be the tool's own scratch/ (or below it), and it
    may not be or contain the tool directory. The executor confines every write to
    a name directly under its root, so a root allowed at the wrong place lets a
    scratch-scoped grant naming `seen.json` or `revocations.jsonl` replace
    enforcement state atomically, or a grant naming `natively` replace the wrapper
    (round-19 gate, finding 4; Fable E8). Returns the resolved scratch dir. Raises
    ValueError before any file is touched — the same class and the same rule shape
    as `check_separation` for the keys. Below the deepest existing ancestor the
    names are compared folded (`_fold`): absent names that differ only by case or
    Unicode normalization count as one name, and the message says so."""
    sd = Path(scratch_dir).expanduser().resolve()
    pairs = (("the state directory", Path(state_dir)), ("the code directory", CODE_DIR))
    for label, other in pairs:
        o = Path(other).expanduser().resolve()
        if _same(sd, o):
            raise ValueError(
                f"scratch dir {sd} is {label} {o}; the executor's root never is{ALIAS}"
            )
        if _within(sd, o):
            raise ValueError(f"scratch dir {sd} is inside {label} {o}; refusing{ALIAS}")
        if _within(o, sd):
            raise ValueError(f"{label} {o} is inside the scratch dir {sd}; refusing{ALIAS}")
    own = PACKAGE_DIR / "scratch"
    if _same(sd, PACKAGE_DIR) or _within(PACKAGE_DIR, sd):
        raise ValueError(f"scratch dir {sd} is or contains the package directory {PACKAGE_DIR}")
    if _within(sd, PACKAGE_DIR) and not _same(sd, own) and not _within(sd, own):
        raise ValueError(
            f"scratch dir {sd} is inside the package directory {PACKAGE_DIR} but is not its "
            f"own scratch/ ({own}); refusing"
        )
    return sd


def check_scratch_identity(scratch_dir: Path, *, state_dir: Path) -> None:
    """The separation of the executor's root from the state directory, the code and
    the package, judged AGAIN once both directories EXIST — by filesystem identity
    alone (the (device, inode) of every ancestor, `_identity` with an empty
    remainder), no fold involved. `check_scratch_separation` runs before either
    is created and folds the absent remainder as the interpreter's Unicode tables
    allow; a case pair those tables do not know (Unicode 15 and 16 added pairs
    this kernel folds — U+1C89/U+1C8A, U+A7CB/U+0264, the Garay letters; round-20
    Fable read, N2) or a fold formula's blind spot (N1) passes it, and the node
    then creates ONE directory under two names. This check sees that: the node
    runs it right after it created both and before it writes anything under
    either (`Node.__init__`). Raises ValueError naming the identity, like the
    other separation checks; the two empty directories are all that exists."""
    sd = Path(scratch_dir).expanduser()
    if _identity(sd)[1] or _identity(Path(state_dir).expanduser())[1]:
        raise ValueError(
            f"scratch dir {sd} or state dir {state_dir} does not exist yet; the identity "
            f"re-check runs once both were created"
        )
    for label, other in (
        ("the state directory", Path(state_dir).expanduser()),
        ("the code directory", CODE_DIR),
        ("the package directory", PACKAGE_DIR),
    ):
        o = Path(other).expanduser().resolve()
        if _same(sd, o) and label != "the package directory":
            raise ValueError(
                f"scratch dir {sd} is {label} {o} by filesystem identity (device and inode) "
                f"once created: two names for one directory; refusing before any file is "
                f"written under it"
            )
        if _within(sd, o) and label != "the package directory":
            raise ValueError(
                f"scratch dir {sd} is inside {label} {o} by filesystem identity once created; "
                f"refusing before any file is written under it"
            )
        if _within(o, sd) or (label == "the package directory" and _same(sd, o)):
            raise ValueError(
                f"{label} {o} is or is inside the scratch dir {sd} by filesystem identity "
                f"once created; refusing before any file is written under it"
            )


def check_separation(keys_dir: Path, *, state_dir: Path, scratch_dir: Path) -> Path:
    """The keys directory must not be inside (or be) the package directory, the state
    directory, or the scratch directory, symlinks resolved; nor may either of those
    sit inside the keys directory. Returns the resolved keys dir. Raises ValueError."""
    kd = Path(keys_dir).expanduser().resolve()
    for label, other in (
        ("the package directory", PACKAGE_DIR),
        ("the state directory", Path(state_dir)),
        ("the scratch directory", Path(scratch_dir)),
    ):
        o = Path(other).expanduser().resolve()
        if _same(kd, o) or _within(kd, o):
            raise ValueError(f"keys dir {kd} is inside {label} {o}; private keys never live there")
        if _within(o, kd):
            raise ValueError(f"{label} {o} is inside the keys dir {kd}; refusing")
    return kd


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str, what: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:  # noqa: BLE001 — any decode failure is a verify failure
        raise VerifyError(f"{what}.encoding", "invalid base64") from e


class KeyPair:
    def __init__(self, priv: Ed25519PrivateKey):
        self._priv = priv
        self.public = PREFIX + _b64(
            priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    @classmethod
    def generate(cls) -> KeyPair:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> KeyPair:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def seed(self) -> bytes:
        return self._priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def sign(self, data: bytes) -> str:
        return _b64(self._priv.sign(data))

    def __repr__(self) -> str:  # never print the seed
        return f"KeyPair(public={self.public})"


def public_from_str(s: str, what: str = "key") -> Ed25519PublicKey:
    if not isinstance(s, str) or not s.startswith(PREFIX):
        raise VerifyError(f"{what}.format", f"expected '{PREFIX}<b64>'")
    raw = _unb64(s[len(PREFIX) :], what)
    if len(raw) != 32:
        raise VerifyError(f"{what}.format", "Ed25519 public key must be 32 bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as e:
        raise VerifyError(f"{what}.format", str(e)) from e


def verify(public: str, data: bytes, sig_b64: str, what: str = "sig") -> None:
    """Raise VerifyError unless sig_b64 is `public`'s Ed25519 signature over data."""
    pub = public_from_str(public, what + ".key")
    if not isinstance(sig_b64, str):
        raise VerifyError(f"{what}.format", "signature must be a base64 string")
    sig = _unb64(sig_b64, what)
    if len(sig) != 64:
        raise VerifyError(f"{what}.format", "Ed25519 signature must be 64 bytes")
    try:
        pub.verify(sig, data)
    except InvalidSignature as e:
        raise VerifyError(f"{what}.invalid", f"signature does not verify under {public}") from e


# ---- key files -----------------------------------------------------------------


def key_path(keys_dir: Path, role: str) -> Path:
    return Path(keys_dir) / f"{role}.key"


def save(kp: KeyPair, keys_dir: Path, role: str, *, force: bool = False) -> Path:
    keys_dir = Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    p = key_path(keys_dir, role)
    if p.exists() and not force:
        raise FileExistsError(f"{p} exists; pass force to overwrite")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(_b64(kp.seed()) + "\n")
    os.chmod(p, 0o600)
    (keys_dir / f"{role}.pub").write_text(kp.public + "\n")
    return p


def load(keys_dir: Path, role: str) -> KeyPair:
    p = key_path(keys_dir, role)
    if not p.exists():
        raise FileNotFoundError(f"no {role} key at {p}; run `natively keygen`")
    mode = p.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(f"{p} is mode {mode:o}; refusing to load a group/world-readable key")
    seed = base64.b64decode(p.read_text().strip(), validate=True)
    return KeyPair.from_seed(seed)


def generate_all(keys_dir: Path, *, force: bool = False) -> dict[str, str]:
    """Generate host, agent, and principal stand-in keys. Returns role -> public."""
    out = {}
    for role in ROLES:
        kp = KeyPair.generate()
        save(kp, keys_dir, role, force=force)
        out[role] = kp.public
    return out
