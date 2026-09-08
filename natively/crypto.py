"""Natively crypto: Ed25519 identity, X25519 DH, AEAD, HKDF, Double Ratchet,
Sender Keys. Suite nv1 (spec section 9): libsodium primitives via PyNaCl.

Ed25519 keys are the protocol identity (signing). X25519 keys for DH are
derived from them with the standard birational map, or generated ephemerally.
"""
import copy
import hashlib
import hmac as _hmac
import os
from nacl import bindings
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey as XPriv, PublicKey as XPub
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

from . import jcs

SUITE = "nv1"


# ---------- Ed25519 identity ----------

def gen_signing_key() -> bytes:
    return bytes(SigningKey.generate())  # 32-byte seed


def sign_pub(seed: bytes) -> bytes:
    return bytes(SigningKey(seed).verify_key)


def sign(seed: bytes, msg: bytes) -> bytes:
    return bytes(SigningKey(seed).sign(msg).signature)


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        VerifyKey(pub).verify(msg, sig)
        return True
    except Exception:
        return False


# ---------- Ed25519 <-> X25519 ----------

def ed_pk_to_x(ed_pk: bytes) -> bytes:
    return bindings.crypto_sign_ed25519_pk_to_curve25519(ed_pk)


def ed_sk_to_x(seed: bytes) -> bytes:
    sk_obj = SigningKey(seed)
    sk64 = bytes(sk_obj) + bytes(sk_obj.verify_key)  # libsodium 64-byte form
    return bindings.crypto_sign_ed25519_sk_to_curve25519(sk64)


def x_gen() -> bytes:
    return bytes(XPriv.generate())


def x_pub(x_sk: bytes) -> bytes:
    return bytes(XPriv(x_sk).public_key)


def x_dh(x_sk: bytes, x_pk: bytes) -> bytes:
    return bindings.crypto_scalarmult(x_sk, x_pk)


# ---------- KDF ----------

def hkdf(ikm: bytes, salt: bytes, info: bytes, n: int = 32) -> bytes:
    prk = _hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def kdf_chain(chain_key: bytes):
    """Symmetric ratchet step -> (next_chain_key, message_key)."""
    mk = _hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    nck = _hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return nck, mk


# ---------- AEAD ----------

def aead_encrypt(key: bytes, pt: bytes, aad: bytes = b"") -> bytes:
    # XSalsa20-Poly1305; the AAD is bound by folding it into the key via hkdf
    k2 = hkdf(key, b"nv1-aad", aad) if aad else key
    return bytes(SecretBox(k2).encrypt(pt))


def aead_decrypt(key: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    k2 = hkdf(key, b"nv1-aad", aad) if aad else key
    return bytes(SecretBox(k2).decrypt(ct))


def b64e(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    import base64
    return base64.b64decode(s)


# ---------- Double Ratchet (spec 9.1, pairwise) ----------

# The key agreement a session's root came from. 1 = the pre-triple
# handshake (dh3 duplicated dh2, the responder's identity key absent);
# 2 = the standard X3DH triple. A persisted session records it so a node
# can tell a handshake its peer will derive differently after an upgrade
# from one the peer has already acknowledged.
X3DH_VERSION = 2


class DRSession:
    """Double Ratchet session state. Symmetric chains + DH ratchet,
    skipped-message-key store (capped) for out-of-order delivery."""

    MAX_SKIP = 200

    def __init__(self):
        self.root_key = None       # bytes
        self.send_chain = None     # (dh_sk, chain_key)
        self.recv_chain = None     # (dh_pk_peer, chain_key)
        self.dh_sk = None          # our current ratchet key
        self.dh_pk_peer = None     # peer's current ratchet pub
        self.send_n = 0
        self.recv_n = 0
        self.prev_send_n = 0
        self.skipped = {}          # (peer_dh_pk_b64, n) -> message_key
        self.x3dh_ek = None        # initiator: ephemeral to re-attach until handshake acked
        self.hs_pending = False    # True until peer's first ack proves it could decrypt
        self.agreement = X3DH_VERSION  # the handshake this root came from

    def to_state(self):
        return {
            "root_key": b64e(self.root_key) if self.root_key else None,
            "send_chain": b64e(self.send_chain) if self.send_chain else None,
            "recv_chain": b64e(self.recv_chain) if self.recv_chain else None,
            "dh_sk": b64e(self.dh_sk) if self.dh_sk else None,
            "dh_pk_peer": b64e(self.dh_pk_peer) if self.dh_pk_peer else None,
            "send_n": self.send_n, "recv_n": self.recv_n,
            "prev_send_n": self.prev_send_n,
            "skipped": {k[0] + ":" + str(k[1]): b64e(v) for k, v in self.skipped.items()},
            "x3dh_ek": b64e(self.x3dh_ek) if self.x3dh_ek else None,
            "hs_pending": self.hs_pending,
            "agreement": self.agreement,
        }

    @classmethod
    def from_state(cls, st):
        s = cls()
        s.root_key = b64d(st["root_key"]) if st["root_key"] else None
        s.send_chain = b64d(st["send_chain"]) if st["send_chain"] else None
        s.recv_chain = b64d(st["recv_chain"]) if st["recv_chain"] else None
        s.dh_sk = b64d(st["dh_sk"]) if st["dh_sk"] else None
        s.dh_pk_peer = b64d(st["dh_pk_peer"]) if st["dh_pk_peer"] else None
        s.send_n, s.recv_n, s.prev_send_n = st["send_n"], st["recv_n"], st["prev_send_n"]
        s.skipped = {}
        for k, v in st["skipped"].items():
            pk, n = k.rsplit(":", 1)
            s.skipped[(pk, int(n))] = b64d(v)
        s.x3dh_ek = b64d(st["x3dh_ek"]) if st.get("x3dh_ek") else None
        s.hs_pending = st.get("hs_pending", False)
        s.agreement = st.get("agreement", 1)  # a state written before the field is the old handshake
        return s

    # --- initiator / responder setup (after X3DH root key) ---
    @classmethod
    def init_initiator(cls, root_key, peer_signed_prekey_pk):
        s = cls()
        s.root_key = root_key
        s.dh_sk = x_gen()
        s.dh_pk_peer = peer_signed_prekey_pk
        rk_ck = hkdf(root_key, s._dh(s.dh_sk, s.dh_pk_peer), b"nv1-dr-root", 64)
        s.root_key, s.send_chain = rk_ck[:32], rk_ck[32:]
        return s

    @classmethod
    def init_responder(cls, root_key, own_signed_prekey_sk):
        s = cls()
        s.root_key = root_key
        s.dh_sk = own_signed_prekey_sk
        return s

    def _dh(self, sk, pk):
        return x_dh(sk, pk)

    def _ratchet_step_recv(self, new_peer_pk, prev_chain_len):
        # store the old chain's remaining keys (up to the length the peer's
        # header declares), then DH ratchet
        if self.recv_chain is not None:
            self._skip_to(prev_chain_len)
        self.prev_send_n = self.send_n
        self.send_n = 0
        self.recv_n = 0
        self.dh_pk_peer = new_peer_pk
        rk_ck = hkdf(self.root_key, self._dh(self.dh_sk, new_peer_pk), b"nv1-dr-root", 64)
        self.root_key, self.recv_chain = rk_ck[:32], rk_ck[32:]
        self.dh_sk = x_gen()
        rk_ck2 = hkdf(self.root_key, self._dh(self.dh_sk, new_peer_pk), b"nv1-dr-root", 64)
        self.root_key, self.send_chain = rk_ck2[:32], rk_ck2[32:]

    # beyond MAX_SKIP the skipped-key store would grow unboundedly; beyond
    # MAX_FFWD the gap is adversarial and refused. Between them the relay's
    # lossy reality applies (a hub that dropped deep backlog): the chain
    # fast-forwards WITHOUT storing keys for the part of the gap that will
    # not fit the store - those messages are gone either way - and keeps
    # the newest MAX_SKIP, so the channel heals instead of wedging.
    MAX_FFWD = 100000

    def _skip_to(self, until):
        """Derive the message keys from recv_n up to `until` (exclusive),
        storing at most the newest MAX_SKIP of them. A gap beyond MAX_FFWD
        is refused before anything is derived. Runs on the working copy;
        the caller commits only after the AEAD verifies."""
        if self.recv_chain is None:
            return
        if until - self.recv_n > self.MAX_FFWD:
            raise CryptoError("skip window exceeded")
        store_from = max(self.recv_n, until - self.MAX_SKIP)
        while self.recv_n < until:
            self.recv_chain, mk = kdf_chain(self.recv_chain)
            if self.recv_n >= store_from:
                self.skipped[(b64e(self.dh_pk_peer), self.recv_n)] = mk
            self.recv_n += 1
        while len(self.skipped) > self.MAX_SKIP:
            self.skipped.pop(next(iter(self.skipped)))

    @staticmethod
    def _header_bytes(hdr) -> bytes:
        """The ratchet header as bound into the AEAD: its JCS form, so a
        peer in any language derives the same bytes."""
        return jcs.canonicalize({"dh": hdr["dh"], "n": hdr["n"], "pn": hdr["pn"]})

    def encrypt(self, pt: bytes, aad: bytes = b""):
        self.send_chain, mk = kdf_chain(self.send_chain)
        hdr = {"dh": b64e(x_pub(self.dh_sk)), "n": self.send_n, "pn": self.prev_send_n}
        ct = aead_encrypt(mk, pt, aad + self._header_bytes(hdr))
        self.send_n += 1
        return hdr, ct

    def decrypt(self, hdr, ct: bytes, aad: bytes = b""):
        """Decrypt one message. Every ratchet step, chain advance and
        skipped-key change is computed on a working copy and committed to
        this session only after the AEAD verifies: a forged or misrouted
        ciphertext leaves the session exactly as it was."""
        peer_pk = b64d(hdr["dh"])
        n, pn = hdr["n"], hdr["pn"]
        if not isinstance(n, int) or not isinstance(pn, int) or isinstance(n, bool) or isinstance(pn, bool) or n < 0 or pn < 0:
            raise CryptoError("bad ratchet header")
        h = aad + self._header_bytes(hdr)
        key_id = (hdr["dh"], n)
        if key_id in self.skipped:
            pt = aead_decrypt(self.skipped[key_id], ct, h)
            del self.skipped[key_id]
            return pt
        w = copy.copy(self)
        w.skipped = dict(self.skipped)
        if w.dh_pk_peer != peer_pk:
            w._ratchet_step_recv(peer_pk, pn)
        if w.recv_chain is None:
            # responder first receive: peer used X3DH root as send chain seed;
            # derive recv chain from root + our signed prekey
            rk_ck = hkdf(w.root_key, w._dh(w.dh_sk, peer_pk), b"nv1-dr-root", 64)
            w.root_key, w.recv_chain = rk_ck[:32], rk_ck[32:]
        w._skip_to(n)
        w.recv_chain, mk = kdf_chain(w.recv_chain)
        w.recv_n += 1
        pt = aead_decrypt(mk, ct, h)
        self.__dict__.update(w.__dict__)
        return pt


# ---------- X3DH-style session start (spec 9.1) ----------

def x3dh_initiator(ik_seed: bytes, peer_ik_pub: bytes, spk_peer_xpk: bytes, opk_peer_xpk: bytes = None):
    """Initiator side of the X3DH triple: IK_A*SPK_B, EK_A*IK_B, EK_A*SPK_B
    (plus EK_A*OPK_B when a one-time prekey is given). Both identity keys
    enter the agreement, so only the holder of the responder's identity
    key (not merely its signed prekey) can derive the root. peer_ik_pub is
    the responder's Ed25519 node key. Returns (root_key, ephem_xpk)."""
    ik_x = ed_sk_to_x(ik_seed)
    ek = x_gen()
    peer_ik_x = ed_pk_to_x(peer_ik_pub)
    dh1 = x_dh(ik_x, spk_peer_xpk)
    dh2 = x_dh(ek, peer_ik_x)
    dh3 = x_dh(ek, spk_peer_xpk)
    ikm = dh1 + dh2 + dh3
    if opk_peer_xpk:
        ikm += x_dh(ek, opk_peer_xpk)
    return hkdf(ikm, b"\x00" * 32, b"nv1-x3dh"), x_pub(ek)


def x3dh_responder(ik_seed: bytes, spk_x_sk: bytes, peer_ik_xpk: bytes, ephem_xpk: bytes, opk_x_sk: bytes = None):
    """Responder side of the same triple: SPK_B*IK_A, IK_B*EK_A, SPK_B*EK_A."""
    ik_x = ed_sk_to_x(ik_seed)
    dh1 = x_dh(spk_x_sk, peer_ik_xpk)
    dh2 = x_dh(ik_x, ephem_xpk)
    dh3 = x_dh(spk_x_sk, ephem_xpk)
    ikm = dh1 + dh2 + dh3
    if opk_x_sk:
        ikm += x_dh(opk_x_sk, ephem_xpk)
    return hkdf(ikm, b"\x00" * 32, b"nv1-x3dh")


# ---------- Sender Keys (spec 9.1, groups) ----------

class SenderKey:
    """Per-(group, sender) hash-ratchet sender key."""

    MAX_SKIP = 200

    def __init__(self, chain_key: bytes = None, n: int = 0):
        self.chain_key = chain_key or os.urandom(32)
        self.n = n
        self.skipped = {}  # n -> message key (out-of-order window)

    def encrypt(self, pt: bytes, aad: bytes = b""):
        self.chain_key, mk = kdf_chain(self.chain_key)
        ct = aead_encrypt(mk, pt, aad)
        n, self.n = self.n, self.n + 1
        return n, ct

    # beyond MAX_SKIP the skipped-key store would grow unboundedly; beyond
    # MAX_FFWD the gap is adversarial and refused. Between them the relay's
    # lossy reality applies: a hub that dropped deep backlog (retention cap)
    # makes the gap unrecoverable, so fast-forward WITHOUT storing keys -
    # those messages are gone either way, and the stream must heal instead of
    # poisoning every later message from this sender (break #16).
    MAX_FFWD = 100000

    def decrypt_at(self, n: int, ct: bytes, aad: bytes = b""):
        """Decrypt message n. The chain is advanced on working values and
        committed only after the AEAD verifies: a forged ciphertext never
        moves the chain or burns a stored key."""
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise CryptoError("bad sender-key index")
        if n in self.skipped:
            pt = aead_decrypt(self.skipped[n], ct, aad)
            del self.skipped[n]
            return pt
        if n < self.n:
            raise CryptoError("replayed/old sender-key message")
        if n - self.n > self.MAX_FFWD:
            raise CryptoError("sender-key gap beyond fast-forward bound")
        ck, cur, stored = self.chain_key, self.n, {}
        if n - cur > self.MAX_SKIP:
            while cur < n:  # lossy fast-forward, no skipped-key storage
                ck, _ = kdf_chain(ck)
                cur += 1
        else:
            while cur < n:
                ck, mk = kdf_chain(ck)
                stored[cur] = mk
                cur += 1
        ck, mk = kdf_chain(ck)
        cur += 1
        pt = aead_decrypt(mk, ct, aad)
        # committed only now: a forged or misrouted ciphertext leaves the
        # key exactly as it was
        self.chain_key, self.n = ck, cur
        self.skipped.update(stored)
        # the store is bounded across gaps, not only per gap: the oldest
        # keys go first (their messages are the least likely to still
        # arrive), so a persisted state never outgrows what from_state
        # accepts
        while len(self.skipped) > self.MAX_SKIP:
            del self.skipped[min(self.skipped)]
        return pt

    def state(self):
        return {"ck": b64e(self.chain_key), "n": self.n,
                "skipped": {str(k): b64e(v) for k, v in self.skipped.items()}}

    @classmethod
    def from_state(cls, st):
        """A SenderKey from state(). Any other shape is CryptoError: a
        32-byte chain key, a non-negative integer counter, and skipped
        keys of 32 bytes under integer indexes. A counter that is not an
        integer would otherwise install fine and fail at the first
        decrypt, after a grant use was spent on the join. A state written
        before the store was bounded may hold more than MAX_SKIP skipped
        keys: it loads, keeping the newest MAX_SKIP, never disabling the
        group."""
        try:
            if not isinstance(st, dict) or not set(st) <= {"ck", "n", "skipped"}:
                raise ValueError
            ck, n = b64d(st["ck"]), st["n"]
            if len(ck) != 32 or isinstance(n, bool) or not isinstance(n, int) or n < 0:
                raise ValueError
            raw = st.get("skipped", {})
            if not isinstance(raw, dict):
                raise ValueError
            skipped = {}
            for k, v in raw.items():
                i, mk = int(k), b64d(v)
                if i < 0 or len(mk) != 32:
                    raise ValueError
                skipped[i] = mk
        except Exception:
            raise CryptoError("not a sender-key state")
        for i in sorted(skipped)[:max(0, len(skipped) - cls.MAX_SKIP)]:
            del skipped[i]
        s = cls(ck, n)
        s.skipped = skipped
        return s
