import common
from nostrclient.relay_pool import RelayPool
from nostrclient.log import log
import datetime
from nostrclient.key import PrivateKey
from nostrclient.localStorage import local_storage
from nostrclient.user import User

Keypriv = local_storage.get("Keypriv")
pkey = PrivateKey(Keypriv)
if Keypriv is None :
    local_storage.set("Keypriv",str(pkey))
print("Your public key: ",pkey.public_key)
print("Your public key bech32: ",pkey.public_key.bech32())


relayServer =  [ 
  "wss://nostr.tbai.me:592/",
  'wss://relay2.nostrchat.io',
  'wss://relay.damus.io',
  'wss://strfry.iris.to',
  'wss://nos.lol',
];

hub = "wss://bridge.duozhutuan.com/";
#hub = "ws://localhost:8088/";

relays = [hub + relay for relay in relayServer]


r = RelayPool(relays)

r.connect(5)
user = User(pkey.public_key,r)

event = user.fetchProfile()
if event is not None:
    print(event)
else:
    print("No user Profile")
