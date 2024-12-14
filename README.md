# NIPY
NIPY, a Python client for Nostr.

## install
```
git clone https://github.com/duozhutuan/NIPY
cd NIPY
pip3 install NIPY --break-system-packages
```

## subscribe filters

```
filters    = {"kinds":[1],"limit":100}

r = Relay(relays[0])

r.connect(5)

def handler_event(event):
    print(event['content'])

r.subscribe(filters)
r.on("EVENT",handler_event)

```

## key
```
from NIPY.key import PrivateKey
from NIPY.localStorage import local_storage

Keypriv = local_storage.get("Keypriv")
pkey = PrivateKey(Keypriv)
if Keypriv is None :
    local_storage.set("Keypriv",str(pkey))
print("Your public key: ",pkey.public_key)
print("Your public key bech32: ",pkey.public_key.bech32())

```


## relay add key 
```
r = RelayPool(relays,pkey)

```

## publish
```
content = "The message from NIPY python nostr client."
kind    = 42
tags    =  [['e', 'f412192fdc846952c75058e911d37a7392aa7fd2e727330f4344badc92fb8a22', 'wss://nos.lol', 'root']]
msg = {
        "kind":kind,
        "tags":tags,
        "content":content,
}

r.publish(msg)

```
