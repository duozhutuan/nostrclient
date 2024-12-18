
import json
from dataclasses import dataclass

@dataclass
class Subscription():
    subid:str
    event:dict
    r:None
    def __post_init__(self):
        self.eventids = []
        self.funcs = {}

    def decorator(self,func):
        def wrapper(*args, **kwargs):
            event = args[0]
            if event["id"] in self.eventids:
                return 
            self.eventids.append(event["id"])    
            result = func(*args, **kwargs) 
            return result
        return wrapper

     
    def on(self,eventname,func):
        self.funcs[func] = self.decorator(func)
        self.r.on(eventname+self.subid,self.funcs[func])

    def off(self,eventname,func):
        self.r.off(eventname+self.subid,self.funcs[func])



    