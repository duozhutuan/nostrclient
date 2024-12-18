import common
from nostrclient.relay_pool import RelayPool
from nostrclient.log import log
import datetime
from nostrclient.key import PrivateKey
from nostrclient.localStorage import local_storage
from nostrclient import bech32 

from langdetect import detect  # pip3 install langdetect
from sklearn.feature_extraction.text import TfidfVectorizer


vectorizer = TfidfVectorizer()


def get_keywords(text):
  try:
    X = vectorizer.fit_transform([(text)])

    indices = X[0].nonzero()[1]
    features = vectorizer.get_feature_names_out()
    keywords = [features[i] for i in indices]

    # 排序并选取前几个关键字
    sorted_keywords = sorted(keywords, key=lambda x: -X[0, vectorizer.vocabulary_[x]])
    top_keywords = sorted_keywords[:3]

   
    return top_keywords
  except:
    return None

Keypriv = local_storage.get("Keypriv")
pkey = PrivateKey(Keypriv)
if Keypriv is None :
    local_storage.set("Keypriv",str(pkey))
print("Your public key: ",pkey.public_key)
print("Your public key bech32: ",pkey.public_key.bech32())


relayServer =  [ 
  'wss://relay.damus.io',
  'wss://strfry.iris.to',
  'wss://nos.lol',
];

hub = "wss://bridge.duozhutuan.com/";
#hub = "ws://localhost:8088/";

relays = [hub + relay for relay in relayServer]

filters    = {"kinds":[1],"limit":100}

r = RelayPool(relays)

r.connect(5)

def detect_lang(text):
    try:
        return detect(text)
    except:
        return None

def bech32encode(rawid):
    converted_bits = bech32.convertbits(rawid, 8, 5)
    return bech32.bech32_encode("note", converted_bits, bech32.Encoding.BECH32)

def handler_event(event):
    dt_object = datetime.datetime.fromtimestamp(event['created_at'])
    log.blue(dt_object.strftime('%Y-%m-%d %H:%M:%S'),False)
    print(f"https://jumble.social/notes/{event['id']}")
    noteid = bech32encode(bytes.fromhex(event['id']))
    print(f"https://yakihonne.com/notes/{noteid}")
    lang = detect_lang(event['content'])
    kw = get_keywords(event["content"])
    print(lang,kw)

subs =r.subscribe(filters)
subs.on("EVENT",handler_event)
