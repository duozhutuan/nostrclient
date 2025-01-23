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

## add nip19 for nprofile,nevent,naddr
```
"""
e = "nevent1qgst9e5yw8k6c4rc6sj3cvhzlpk0m250vef6rgv8rzxcrk7sf3nwaecqyp2fff55rmsux0p3aj5v4gyaum7vhn56l5yadd8u3p7enjyvjg3dvuqapge"
print(decode_bech32(e))
p="nprofile1qyw8wumn8ghj7mn0wd68ytfsxyh8jcttd95x7mnwv5hxxmmdqyw8wumn8ghj7mn0wd68ytfsxgh8jcttd95x7mnwv5hxxmmdqy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsz9nhwden5te0wfjkccte9ehx7um5wghxyctwvsq3samnwvaz7tmwdaehgu3ww33xz6fwd4jn5dfexghszrnhwden5te0dehhxtnvdakz7qpqs02jksmr6tgmcksf3hnmue7pyzlm0sxwarh7lk8tdeprw2hjg6ysu92gue"
print(decode_bech32(p))
a = "naddr1qvzqqqy9hvpzq3le048q5eqv32tr60a8rk0s564djk9055zlal0d6m2jnm6pythnqqjxgcny89jnyc3494jkyvfc956xzvfs943xxc3n95ckxvn9xcuxvvt9v93nwlq2002"
print(decode_bech32(a))
"""

"""
p1 = {'relays': ['wss://nostr-01.yakihonne.com', 'wss://nostr-02.yakihonne.com', 'wss://relay.damus.io', 'wss://relay.nostr.band', 'wss://nostr.tbai.me:592/', 'wss://nos.lol/'], 'pubkey': '83d52b4363d2d1bc5a098de7be67c120bfb7c0cee8efefd8eb6e42372af24689'}
p2 = encode_bech32("nprofile",p1)
print(p2)
"""
```

## add or delete relay 
```
r = RelayPool(relays)

r.connect(5)

r.add_relay("wss://nostr.mom")

r.del_relay("wss://nostr.mom")

```
