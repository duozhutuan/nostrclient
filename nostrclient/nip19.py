"""
https://github.com/nbd-wtf/nostr-tools/blob/master/nip19.ts
"""

from . import bech32 

def to_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode('utf-8')
    if isinstance(data, int):
        return bytes([data])
    return bytes(data)

def integer_to_uint8_array(number: int) -> bytes:

    hex_str = f"{number:08x}"
    return bytes.fromhex(hex_str)

def tlv_decode(data, tag_map=None):
    """
    解析 TLV 格式的字节流为原始数据。
    """
    tag_map = tag_map or {}
    ret = {}
    i = 0
    while i < len(data) - 1:
        t, length = data[i], data[i + 1]
        v = data[i + 2:i + 2 + length]
        i += 2 + length
        tag_name = tag_map.get(t, {}).get('name', t)
        fmt = tag_map.get(t, {}).get('format', to_bytes)
        tag_value = fmt(v)
        if tag_name in ret:
            ret[tag_name] = [ret[tag_name]] if not isinstance(ret[tag_name], list) else ret[tag_name]
            ret[tag_name].append(tag_value)
        else:
            ret[tag_name] = tag_value
    return ret

def bech32_to_hex(key):
    return bytes_to_hex(bech32.convertbits(bech32.bech32_decode(key)[1], 5, 8))

def bytes_to_hex(data):
    return ''.join(f"{i:02x}" for i in data)

def bytes_to_str(data):
    data = ''.join(chr(i) for i in data)
    return data

def bytes_to_int(data):
    return int.from_bytes(data, 'big')

 
def tlv_encode(data, tag_map={}):
    """
    将原始数据编码为 TLV 格式的字节流。
    """
    result = []
    
    # 优先遍历 tag_map
    for tag, info in tag_map.items():
        tag_name = info.get('name')
        if tag_name in data:  # 如果 tag_name 在 data 中存在
            value = data[tag_name]
            fmt = info.get('format', to_bytes)  # 获取 format，默认为 to_bytes
            
            # 将 value 转换为字节数组
            if isinstance(value, list):
                # 如果 value 是列表，逐个处理
                for v in value:
                    encoded_value = fmt(v)
                    result.extend([tag, len(encoded_value)])
                    result.extend(encoded_value)
            else:
                # 如果 value 是单个值
                encoded_value = fmt(value)
                result.extend([tag, len(encoded_value)])
                result.extend(encoded_value)
    return bytes(result)

def encode_bech32(name, data):
    """
    将原始数据编码为 bech32 格式的字符串。
    """
    # 定义 tag_map
    tag_map = {
        'nprofile': {
            0x00: {'name': 'pubkey', 'format': bytes.fromhex},
            0x01: {'name': 'relay', 'format': to_bytes}
        },
        'nevent': {
            0x00: {'name': 'id', 'format': bytes.fromhex},
            0x01: {'name': 'relay', 'format': to_bytes},
            0x02: {'name': 'author', 'format': bytes.fromhex},
            0x03: {'name': 'kind', 'format': integer_to_uint8_array}
        },
        'naddr': {
            0x00: {'name': 'id', 'format': bytes.fromhex},
            0x02: {'name': 'author', 'format': bytes.fromhex},
            0x03: {'name': 'kind', 'format': integer_to_uint8_array}
        }
    }

    # 根据 name 获取对应的 tag_map
    current_tag_map = tag_map.get(name)

    # 将数据编码为 TLV 格式
    tlv_data = tlv_encode(data, current_tag_map)

    # 将 TLV 数据转换为 5-bit 数组
    converted_bits = bech32.convertbits(tlv_data, 8, 5)

    # 生成 bech32 编码字符串
    return bech32.bech32_encode(name, converted_bits)


def decode_bech32(value):
    hrp,data = bech32.bech32_decode(value)
    data   = bech32.convertbits(data, 5, 8)
    tag_map = {
        'nprofile': {0x00: {'name': 'pubkey', 'format': bytes_to_hex}, 
        	     0x01: {'name': 'relays', 'format': bytes_to_str}},
        'nevent': {0x00: {'name': 'id', 'format': bytes_to_hex}, 
        	   0x01: {'name': 'relays', 'format': bytes_to_str}, 
        	   0x02: {'name': 'author', 'format': bytes_to_hex}, 
        	   0x03: {'name': 'kind', 'format': bytes_to_int}},         
        'naddr':  {0x00: {'name': 'identifier', 'format': bytes_to_str}, 
        	   0x02: {'name': 'author', 'format': bytes_to_hex}, 
        	   0x03: {'name': 'kind', 'format': bytes_to_int}}
    }
    return tlv_decode(data, tag_map.get(hrp))

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

