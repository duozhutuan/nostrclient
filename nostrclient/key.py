import secrets
import base64
import secp256k1
from cffi import FFI
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from hashlib import sha256

from .event import Event, EventKind
from . import bech32


import time
from dataclasses import dataclass


@dataclass
class Delegation:
    delegator_pubkey: str
    delegatee_pubkey: str
    event_kind: int
    duration_secs: int = 30*24*60  # default to 30 days
    signature: str = None  # set in PrivateKey.sign_delegation

    @property
    def expires(self) -> int:
        return int(time.time()) + self.duration_secs
    
    @property
    def conditions(self) -> str:
        return f"kind={self.event_kind}&created_at<{self.expires}"
    
    @property
    def delegation_token(self) -> str:
        return f"nostr:delegation:{self.delegatee_pubkey}:{self.conditions}"

    def get_tag(self) -> list[str]:
        """ Called by Event """
        return [
            "delegation",
            self.delegator_pubkey,
            self.conditions,
            self.signature,
        ]



class PublicKey:
    def __init__(self, raw_bytes: bytes=None) -> None:
        self.raw_bytes = raw_bytes

    def bech32(self) -> str:
        converted_bits = bech32.convertbits(self.raw_bytes, 8, 5)
        return bech32.bech32_encode("npub", converted_bits)

    def hex(self) -> str:
        return self.raw_bytes.hex()

    def verify_signed_message_hash(self, hash: str, sig: str) -> bool:
        pk = secp256k1.PublicKey(b"\x02" + self.raw_bytes, True)
        return pk.schnorr_verify(bytes.fromhex(hash), bytes.fromhex(sig), None, True)

    @classmethod
    def from_npub(cls, npub: str):
        """ Load a PublicKey from its bech32/npub form """
        hrp, data = bech32.bech32_decode(npub)
        raw_public_key = bech32.convertbits(data, 5, 8)[:-1]
        return cls(bytes(raw_public_key))

    def __str__(self):
        return self.hex()

    def __repr__(self):
        return self.hex()


class PrivateKey:
    def __init__(self, data = None) -> None:
        if data is None:
            self.raw_secret = secrets.token_bytes(32)
        elif isinstance(data, bytes):
            self.raw_secret = data
        elif isinstance(data, str):
            if data.startswith("nsec"):
                hrp, data = bech32.bech32_decode(data)
                self.raw_secret = bytes(bech32.convertbits(data, 5, 8)[:-1])
                 
            else:
                self.raw_secret = bytes.fromhex(data)
        
        sk = secp256k1.PrivateKey(self.raw_secret)
        self.public_key = PublicKey(sk.pubkey.serialize()[1:])
 

    @classmethod
    def from_nsec(cls, nsec: str):
        """ Load a PrivateKey from its bech32/nsec form """
        hrp, data  = bech32.bech32_decode(nsec)
        raw_secret = bech32.convertbits(data, 5, 8)[:-1]
        return cls(bytes(raw_secret))

    def bech32(self) -> str:
        converted_bits = bech32.convertbits(self.raw_secret, 8, 5)
        return bech32.bech32_encode("nsec", converted_bits)

    def hex(self) -> str:
        return self.raw_secret.hex()

    def tweak_add(self, scalar: bytes) -> bytes:
        sk = secp256k1.PrivateKey(self.raw_secret)
        return sk.tweak_add(scalar)

    def compute_shared_secret(self, public_key_hex: str) -> bytes:
        pk = secp256k1.PublicKey(bytes.fromhex("02" + public_key_hex), True)
        return pk.ecdh(self.raw_secret, hashfn=copy_x)

    def sign_message_hash(self, hash: bytes) -> str:
        sk = secp256k1.PrivateKey(self.raw_secret)
        sig = sk.schnorr_sign(hash, None, raw=True)
        return sig.hex()

    def sign_event(self, event: Event) -> None:
        if event.public_key is None:
            event.public_key = self.public_key.hex()
        event.signature = self.sign_message_hash(bytes.fromhex(event.id))

    def sign_delegation(self, delegation: Delegation) -> None:
        delegation.signature = self.sign_message_hash(sha256(delegation.delegation_token.encode()).digest())

    def __eq__(self, other):
        return self.raw_secret == other.raw_secret

    def __str__(self):
        return self.hex()

def mine_vanity_key(prefix: str = None, suffix: str = None) -> PrivateKey:
    if prefix is None and suffix is None:
        raise ValueError("Expected at least one of 'prefix' or 'suffix' arguments")

    while True:
        sk = PrivateKey()
        if prefix is not None and not sk.public_key.bech32()[5:5+len(prefix)] == prefix:
            continue
        if suffix is not None and not sk.public_key.bech32()[-len(suffix):] == suffix:
            continue
        break

    return sk


ffi = FFI()
@ffi.callback("int (unsigned char *, const unsigned char *, const unsigned char *, void *)")
def copy_x(output, x32, y32, data):
    ffi.memmove(output, x32, 32)
    return 1
