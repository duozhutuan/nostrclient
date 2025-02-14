import time
import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List
from secp256k1 import PublicKey
from hashlib import sha256

from . import bech32



class EventKind(IntEnum):
    SET_METADATA = 0
    TEXT_NOTE = 1
    RECOMMEND_RELAY = 2
    CONTACTS = 3
    ENCRYPTED_DIRECT_MESSAGE = 4
    DELETE = 5



@dataclass
class Event:
    content: str = None
    public_key: str = None
    created_at: int = None
    kind: int = EventKind.TEXT_NOTE
    tags: List[List[str]] = field(default_factory=list)  # Dataclasses require special handling when the default value is a mutable type
    signature: str = None


    def __post_init__(self):
        if self.content is not None and not isinstance(self.content, str):
            # DMs initialize content to None but all other kinds should pass in a str
            raise TypeError("Argument 'content' must be of type str")

        if self.created_at is None:
            self.created_at = int(time.time())


    @staticmethod
    def serialize(public_key: str, created_at: int, kind: int, tags: List[List[str]], content: str) -> bytes:
        data = [0, public_key, created_at, kind, tags, content]
        data_str = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        return data_str.encode()


    @staticmethod
    def compute_id(public_key: str, created_at: int, kind: int, tags: List[List[str]], content: str):
        return sha256(Event.serialize(public_key, created_at, kind, tags, content)).hexdigest()


    @property
    def id(self) -> str:
        # Always recompute the id to reflect the up-to-date state of the Event
        return Event.compute_id(self.public_key, self.created_at, self.kind, self.tags, self.content)


    @property
    def note_id(self) -> str:
        converted_bits = bech32.convertbits(bytes.fromhex(self.id), 8, 5)
        return bech32.bech32_encode("note", converted_bits)


    def add_pubkey_ref(self, pubkey:str):
        """ Adds a reference to a pubkey as a 'p' tag """
        self.tags.append(['p', pubkey])


    def add_event_ref(self, event_id:str):
        """ Adds a reference to an event_id as an 'e' tag """
        self.tags.append(['e', event_id])


    def verify(self) -> bool:
        pub_key = PublicKey(bytes.fromhex("02" + self.public_key), True)  # add 02 for schnorr (bip340)
        return pub_key.schnorr_verify(bytes.fromhex(self.id), bytes.fromhex(self.signature), None, raw=True)


    def message(self) -> str:
        return json.dumps(
            [
                "EVENT",
                {
                    "id": self.id,
                    "pubkey": self.public_key,
                    "created_at": self.created_at,
                    "kind": self.kind,
                    "tags": self.tags,
                    "content": self.content,
                    "sig": self.signature
                }
            ]
        )



