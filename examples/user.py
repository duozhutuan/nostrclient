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
  'pubkey/25ab88fc19432f1c35ced742122ec57a41398ec7c50997fd08c29ca79cbe3b71',
];

hub = "wss://bridge.duozhutuan.com/";
#hub = "ws://localhost:8088/";

relays = [hub + relay for relay in relayServer]


r = RelayPool(relays,pkey)

r.connect(5)

user = User(pkey.public_key,r)

profile = user.fetchProfile()
if profile is not None:
    print(profile)
else:
    print("No user Profile")

user.profile.website = "https://github.com/duozhutuan/NorstrBridge"
user.update()
