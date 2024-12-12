import common
from relay import Relay

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

#hub = "wss://bridge.duozhutuan.com/";
hub = "ws://localhost:8088/";

relays = [hub + relay for relay in relayServer]

filters    = {"kinds":[1],"limit":100}

r = Relay(relays[0])

r.connect(5)

def handler_event(event):
    print(event['content'])

r.subscribe(filters)
r.on("EVENT",handler_event)
