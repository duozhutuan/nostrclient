from .relay import Relay
from dataclasses import dataclass
from queue import Queue
from typing import List
from threading import Condition
from .subscription import Subscription
from .log import log
from .key import PrivateKey
from .event import Event
import threading
import time
import json
import queue
import asyncio

@dataclass
class RelayPool:
    urls: List[str]
    Privkey: PrivateKey = None 

    def __post_init__(self):
        self.listeners       = {}
        self.eventsqueue      = Queue()
        self.RelayList = [ Relay(url,self.Privkey) for url in self.urls]
        threading.Thread(
            target=self.emitevents,      
        ).start()
        self.serial  = 0;


    def connect(self,timeout=10):
        for r in self.RelayList:
            r.connect(timeout)

    
    def close(self):
        for r in self.RelayList:
            r.close()

    def emitevents(self):
        while True:

            try:
                eventname, args = self.eventsqueue.get(timeout=0.1)
                if eventname in self.listeners:
                    for listener in self.listeners[eventname]:
                        listener(args)
            except queue.Empty:
                continue 

    def on(self,eventname,func):
        if eventname not in self.listeners:
            self.listeners[eventname] = []
        self.listeners[eventname].append(func)

    def off(self,eventname,func):
        if eventname in self.listeners:
            try:
                self.listeners[eventname].remove(func)
            except ValueError:
                pass  # 如果函数不在列表中，就忽略这个错误

    def emit(self,eventname,args):
        self.eventsqueue.put((eventname,args))

    def subscribe(self,event):
        self.serial  += 1;
        subs = Subscription(f'pool-sub-{self.serial}',event,self) 
        def handler_events(event): 
            self.emit("EVENT"+subs.subid,event)
            
        for r in self.RelayList:
            sub = r.subscribe(event)
            sub.on("EVENT",handler_events)
            sub.handler_events = handler_events
            subs.sublist.append(sub)


        return subs 

    def fetchEvent(self,event,timeout = 2):
        self.serial  += 1;
        subs = Subscription(f'pool-sub-{self.serial}',event,self) 
 
        server_relpy = Condition()
        ret_event = None 
        
        eose_count = 0
        def finish(e):
            nonlocal ret_event
            ret_event = e
            
            with server_relpy:             
                server_relpy.notify()
        def done(e):
            nonlocal eose_count 
            eose_count += 1
            if eose_count < len(self.RelayList):
                return 

            with server_relpy:             
                server_relpy.notify()
            
        for r in self.RelayList:
            sub = r.fetchEvent(event,timeout=None)
            sub.on("EVENT",finish)
            r.on("EOSE", done)

        with server_relpy:
            server_relpy.wait(timeout)
        
        return ret_event 

    def publish(self,event):
        if self.Privkey is None:
            log.red("Publish need Private key to sign!");
            return 
        if isinstance(event, dict):
            e = Event(event['content'])
            if 'pubkey' in event:
                e.public_key =  event['pubkey']
            if 'created_at' in event:
                e.created_at = event['created_at']

            if 'kind' in event:
                e.kind = event['kind']

            if 'tags' in event:
                e.tags = event['tags']

        if isinstance(event, Event):
            e = event
        if e.signature == None: 
            self.Privkey.sign_event(e)
        
        for r in self.RelayList:
            r.publish(e)
        return e     
