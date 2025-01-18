import common
from nostrclient.relay_pool import RelayPool
from nostrclient.log import log
import datetime
from nostrclient.key import PrivateKey
from nostrclient.localStorage import local_storage
from nostrclient.actions import like_event

Keypriv = local_storage.get("Keypriv")
pkey = PrivateKey(Keypriv)
if Keypriv is None :
    local_storage.set("Keypriv",str(pkey))
print("Your public key: ",pkey.public_key)
print("Your public key bech32: ",pkey.public_key.bech32())


relayServer =  [ 
  "wss://nostr.tbai.me:592/",
  'wss://relay1.nostrchat.io',
  'wss://relay2.nostrchat.io',
  'wss://relay.damus.io',
  'wss://strfry.iris.to',
  'wss://nos.lol',
 # 'pubkey/25ab88fc19432f1c35ced742122ec57a41398ec7c50997fd08c29ca79cbe3b71',  
];

hub = "wss://bridge.duozhutuan.com/";
#hub = "ws://localhost:8088/";

relays = [hub + relay for relay in relayServer]

filters    = {"kinds":[1],"limit":100}

r = RelayPool(relays)

r.connect(5)

r1 = RelayPool(relays,pkey)
r1.connect(5)

def handler_event(event):
    dt_object = datetime.datetime.fromtimestamp(event['created_at'])
    log.blue(dt_object.strftime('%Y-%m-%d %H:%M:%S'),False)
    print(event['id'])
    print(event['content'])



subs = r.subscribe(filters)
subs.on("EVENT",handler_event)
