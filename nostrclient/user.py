from dataclasses import dataclass



@dataclass
class User:
    pubkey:str
    r:None 
    def __post_init__(self):
        self.pubkey = str(self.pubkey)

    def Event(self):
        return {
            "kinds": [0],
            "authors": [self.pubkey]}

    def fetchProfile(self):
        return self.r.fetchEvent(self.Event())
        
