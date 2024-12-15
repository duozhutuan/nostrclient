import common
from NOPY.relay_pool import RelayPool
from NOPY.log import log
import datetime
from NOPY.key import PrivateKey
from NOPY.localStorage import local_storage

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
#  'wss://theforest.nostr1.com/',
];

hub = "wss://bridge.duozhutuan.com/";
#hub = "ws://localhost:8088/";

relays = [hub + relay for relay in relayServer]


r = RelayPool(relays,pkey)

r.connect(5)

content = "The message from NOPY python nostr client."
kind    = 42
tags    =  [['e', 'f412192fdc846952c75058e911d37a7392aa7fd2e727330f4344badc92fb8a22', 'wss://nos.lol', 'root']]
msg = {
        "kind":kind,
        "tags":tags,
        "content":content,
}

r.publish(msg)

