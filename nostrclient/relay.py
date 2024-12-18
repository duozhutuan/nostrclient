from websocket import WebSocketApp
from dataclasses import dataclass
from queue import Queue
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
class Relay:
    url: str
    Privkey: PrivateKey = None 

    def __post_init__(self,reconnect=False):
        
        self.connected: bool = False 
        self.reconnecttime   = 5 #default 5S
        self.starttime       = int(time.time())

        self.connection_established = Condition()
        self.ws:WebSocketApp = WebSocketApp(
            self.url,
            on_open    = self._on_open,
            on_message = self._on_message,
            on_error   = self._on_error,
            on_close   = self._on_close
        )
        if reconnect == False :
            self.serial          = 0
            self.listeners       = {}
            self.eventqueue      = Queue()         
            threading.Thread(
                target=self.emitevent,
             ).start()

            self.on("CLOSE",self.reconnect)
             

    def emitevent(self):
        while True:

            try:
                eventname, args = self.eventqueue.get(timeout=0.1)
                
                if eventname in self.listeners:
                    for listener in self.listeners[eventname]:
                        listener(args)
 

            except queue.Empty:
                continue 

    def connect(self,timeout=10):
        
        self.run_thread = threading.Thread(
            target=self.ws.run_forever,
           
        )

        self.run_thread.start()         

        with self.connection_established:
            if not self.connected:
                self.connection_established.wait(timeout)
   

    def connecting(self):

        while self.eventqueue.qsize() > 0:
            time.sleep(0.1)
        
        self.ws.keep_running = False 

        since = self.starttime - 60 #To prevent missing messages, go back 60 seconds.
        # set new starttime
        self.__post_init__(reconnect=True);
        self.connect();
        self.emit("reconnect",since)            
           

    def reconnect(self,event): 
            log.yellow(f'reconnect relay {self.url}') 
            threading.Thread(
                target=self.connecting,).start()   

    def close(self):
        self.ws.close()

    def send(self,message):
        if self.connected == False:
            return 
        if isinstance(message, str):
            self.ws.send(message)
        elif isinstance(message, dict):
            json_message = json.dumps(message)
            self.ws.send(json_message)
         

    def publish(self, event):
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

        self.send(e.message());
        
    def subscribe(self,event,sub=None):

        self.serial += 1 
        if sub == None :
            sub = Subscription(f'nostrclient-sub-{self.serial}',event,self)
        
        def resub(since):
            event['since'] = since
            self.send('["REQ", "' + sub.subid +'",' + json.dumps(event) + "]");

        self.on("reconnect",resub)

        self.send('["REQ","' + sub.subid +'",' + json.dumps(event) + "]");
        return sub

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

    def fetchEvent(self,event,timeout=2):
        self.serial += 1 
        sub = Subscription(f'nostrclient-sub-{self.serial}',event,self)
        self.send('["REQ","' + sub.subid +'",' + json.dumps(event) + "]");

        if timeout == None:
            return sub 

        server_relpy = Condition()
        event = None 

        def finish(e):
            event = e
            with server_relpy:             
                server_relpy.notify()
        def done(e):
            with server_relpy:             
                server_relpy.notify()

        sub.on("EVENT",finish)
        sub.on("EOSE", done)

        with server_relpy:
            server_relpy.wait(timeout)

        return event 


    def emit(self,eventname,args):
        self.eventqueue.put((eventname,args))

    def add_subscription(self, id, filters):
        with self.lock:
            self.subscriptions[id] = Subscription(id, filters)

    def close_subscription(self, id: str) -> None:
        with self.lock:
            self.subscriptions.pop(id, None)

    def update_subscription(self, id: str, filters) -> None:
        with self.lock:
            subscription = self.subscriptions[id]
            subscription.filters = filters


 

    def _on_open(self, class_obj):
        with self.connection_established:
            self.connected = True
            self.connection_established.notify()

    def _on_close(self, class_obj, status_code, message):
       
        # 1 emit 2 connected = False 
        self.emit("CLOSE","") 
        self.connected = False
        
        
    def _on_error(self, class_obj, error):
        log.red(error)
        log.blue(f'relay url:{self.url}');

        if self.ws.sock.connected == False:
            self.connected = False
  

    def _on_message(self, ws, message: str):
        """Handle the incoming message."""
 
        
        try:
            data = json.loads(message)
            cmd, id, *rest = data
            
            if cmd == "EVENT":
                self.handle_event(id, *rest)
            elif cmd == "COUNT":
                self.handle_count(id, *rest)
            elif cmd == "EOSE":
                self.handle_eose(id)
            elif cmd == "OK":
                self.handle_ok(id, *rest)
            elif cmd == "CLOSED":
                self.handle_closed(id, *rest)
            elif cmd == "NOTICE":
                self.on_notice(rest[0])
            elif cmd == "AUTH":
                self.on_auth_requested(rest[0])
            else:
                self.debug(f"Unknown command: {cmd}")

        except json.JSONDecodeError as error:
            self.debug(f"Error parsing message from {self.relay_url}: {error}")   
 

       

    # handle message
    
    def handle_event(self, id, rest):
        """Handle the 'EVENT' command."""
        self.emit("EVENT" + id,rest)
 
    def handle_eose(self, id):
        """Handle the 'EOSE' command."""
        self.emit("EOSE" + id,"")    

    def handle_count(self, id, rest):
        """Handle the 'COUNT' command."""
        payload = rest[0]
        count = payload.get("count")
        cr = self.open_count_requests.get(id)
        if cr:
            cr(count)
            del self.open_count_requests[id]

    def handle_ok(self, id, *rest):
        """Handle the 'OK' command."""
        ok = rest[0]
        reason = rest[1]
 
        print("ok",self.url)
        if ok:
            return reason
        else:
            print(reason)
            return reason


    def handle_closed(self, id, rest):
        """Handle the 'CLOSED' command."""
        pass

    def on_notice(self, message):
        """Handle the 'NOTICE' command."""
        self.debug(f"NOTICE: {message}")

    def on_auth_requested(self, message):
        """Handle the 'AUTH' command."""
        self.debug(f"AUTH requested: {message}")
    
    def debug(self,message):
        print(message)


