# nostrclient
nostrclient, a Python client for Nostr.

## install
```
git clone https://github.com/duozhutuan/nostrclient
cd nostrclient
pip3 install nostrclient --break-system-packages
```

## subscribe filters

```
filters    = {"kinds":[1],"limit":100}

r = Relay(relays[0])

r.connect(5)

def handler_event(event):
    print(event['content'])

sub = r.subscribe(filters)
sub.on("EVENT",handler_event)

```

## key
```
from nostrclient.key import PrivateKey
from nostrclient.localStorage import local_storage

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
content = "The message from nostrclient python nostr client."
kind    = 42
tags    =  [['e', 'f412192fdc846952c75058e911d37a7392aa7fd2e727330f4344badc92fb8a22', 'wss://nos.lol', 'root']]
msg = {
        "kind":kind,
        "tags":tags,
        "content":content,
}

r.publish(msg)

```

## fetchEvent and user

```
from nostrclient.user import User
user = User(pkey.public_key,r)

event = user.fetchProfile()
if event is not None:
    print(event)
else:
    print("No user Profile")

```

## like event
```
from nostrclient.actions import like_event
r1.publish(like_event(event['id'],event['pubkey']))
```

For a complete example, see examples/sub.py.

## User

```
user = User(pkey.public_key,r)

profile = user.fetchProfile()
if profile is not None:
    print(profile)
else:
    print("No user Profile")

user.profile.website = "https://github.com/duozhutuan/NorstrBridge"
user.update()

```
