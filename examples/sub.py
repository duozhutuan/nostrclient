import common
from relay_pool import RelayPool
from log import log
import datetime

relayServer =  [ 
  "wss://nostr.tbai.me:592/",
# 'wss://relay1.nostrchat.io',
# 'wss://relay2.nostrchat.io',
  'wss://relay.damus.io',
  'wss://strfry.iris.to',
#  'wss://nos.lol',
#  'wss://theforest.nostr1.com/',
#  'wss://algo.utxo.one/',
];

hub = "wss://bridge.duozhutuan.com/";
#hub = "ws://localhost:8088/";

relays = [hub + relay for relay in relayServer]

filters    = {"kinds":[1],"limit":100}

r = RelayPool(relays)

r.connect(5)

def handler_event(event):
    dt_object = datetime.datetime.fromtimestamp(event['created_at'])
    log.blue(dt_object.strftime('%Y-%m-%d %H:%M:%S'),False)
    print(event['content'])

r.subscribe(filters)
r.on("EVENT",handler_event)
