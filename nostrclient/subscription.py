
import json
from dataclasses import dataclass

@dataclass
class Subscription():
    subid:str
    event:dict
    r:None 
    def on(self,eventname,func):
        self.r.on(eventname+self.subid,func)

    def off(self,eventname,func):
        self.r.off(eventname+self.subid,func)



    