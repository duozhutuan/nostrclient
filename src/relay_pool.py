from relay import Relay
from dataclasses import dataclass
from queue import Queue
from typing import List
from threading import Condition
from subscription import Subscription
from log import log
import threading
import time
import json
import queue


@dataclass
class RelayPool:
    urls: List[str]

    def __post_init__(self):
        self.listeners       = {}
        self.eventsqueue      = Queue()
        self.RelayList = [ Relay(url) for url in self.urls]


    def connect(self,timeout=10):
        for r in self.RelayList:
            r.connect(timeout)

        self.emit_thread = threading.Thread(
            target=self.emitevent,
             
        )
        self.emit_thread.start()

    def emitevent(self):
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
        def handler_events(event): 
            self.emit("EVENT",event)
            
        for r in self.RelayList:
            r.subscribe(event)
            r.on("EVENT",handler_events)
   