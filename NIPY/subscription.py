
import json
from dataclasses import dataclass

@dataclass
class Subscription():
    subid:str
    event:dict

    