 
from dataclasses import dataclass, fields,asdict
from typing import Union, Optional, Dict
import json
from .relay_pool import RelayPool
@dataclass
class UserProfile:
    created_at: Optional[int] = None
    name: Optional[str] = None
    display_name: Optional[str] = None
    displayName: Optional[str] = None
    picture: Optional[str] = None
    banner: Optional[str] = None
    bio: Optional[str] = None
    nip05: Optional[str] = None
    lud06: Optional[str] = None
    lud16: Optional[str] = None
    about: Optional[str] = None
    zapService: Optional[str] = None
    website: Optional[str] = None
    profileEvent: Optional[str] = None

    def from_dict(self, data: dict):
        for field in fields(self):
            if field.name in data:
                setattr(self, field.name, data[field.name])
        self.display_name = self.display_name or self.displayName or self.name

    def to_dict(self):
        return asdict(self)


@dataclass
class User:
    pubkey:str
    r:None 
    def __post_init__(self):
        self.pubkey = str(self.pubkey)
        self.profile = UserProfile ()
    def Event(self):
        return [{
            "kinds": [0],
            "authors": [self.pubkey]},{
            "kinds": [10002],
            "authors": [self.pubkey]},
            ]

    def indexer_relay(self):
        index = self.r.fetchEvent(self.Event()[1])
        if index:
            relays = [r[1] for r in ret.tags if r[0] == "r"]
            return relays
        rx = RelayPool(['wss://purplepag.es','wss://relay.nostr.band'])
        index = rx.fetchEvent(self.Event()[1])
        if index:
            relays = [r[1] for r in ret.tags if r[0] == "r"]
            return relays
        return []

    def fetchProfile(self):
        ret = self.r.fetchEvent(self.Event()[0])
        if ret:
            self.profile.from_dict(json.loads(ret['content']))
            self.profile.created_at = ret['created_at']
        else:
                relays = self.indexer_relay() 
                if len(relays):
                    rp = RelayPool(relays)        
                    rp.connect(0)
                    ret = rp.fetchEvent(self.Event()[0])
                    if ret:
                        self.profile.from_dict(json.loads(ret['content']))
                        self.profile.created_at = ret['created_at']
                
        return self.profile 

    def update(self): 
        event = {
            "kind":0,
            "content": json.dumps(self.profile.to_dict())
           }       
        self.r.publish(event)



        
