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
