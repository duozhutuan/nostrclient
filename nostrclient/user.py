 
from dataclasses import dataclass, fields,asdict
from typing import Union, Optional, Dict
import json

@dataclass
class UserProfile:
    created_at: Optional[int] = None
    name: Optional[str] = None
    displayName: Optional[str] = None
    image: Optional[str] = None
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
        return {
            "kinds": [0],
            "authors": [self.pubkey]}

    def fetchProfile(self):
        
        ret = self.r.fetchEvent(self.Event())
        if ret:
            self.profile.from_dict(json.loads(ret['content']))
        
        return self.profile 

    def update(self): 
        event = {
            "kind":0,
            "content": json.dumps(self.profile.to_dict())
           }       
        self.r.publish(event)



        
