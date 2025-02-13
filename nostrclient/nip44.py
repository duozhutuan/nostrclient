import base64
import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF,HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from coincurve._libsecp256k1 import ffi,lib
import coincurve as secp256k1
from Crypto.Cipher import ChaCha20



# 最小明文大小和最大明文大小
MIN_PLAINTEXT_SIZE = 1
MAX_PLAINTEXT_SIZE = 65535

def tohex(key):
    if isinstance(key,str):
        return bytes.fromhex(key)
    return key 

@ffi.callback(
    "int (unsigned char *, const unsigned char *, const unsigned char *, void *)"
)
def copy_x(output, x32, y32, data):
    ffi.memmove(output, x32, 32)
    return 1

def compute_shared_secret(private_key, public_key_hex):
        assert public_key_hex, "No public key defined"
        
        private_key    = tohex(private_key)

        sk = secp256k1.PrivateKey(private_key)
        result = ffi.new('char [32]')
        pk = secp256k1.PublicKey(bytes.fromhex("02" + public_key_hex))
        res = lib.secp256k1_ecdh(
            sk.context.ctx, result, pk.public_key,  private_key, copy_x, ffi.NULL
        )
        if not res:
            raise Exception(f'invalid scalar ({res})')

        return bytes(ffi.buffer(result, 32))

def get_conversation_key(privkey_a , pubkey_b ) -> bytes:
    """
    获取会话密钥
    :param privkey_a: 私钥
    :param pubkey_b: 公钥
    :return: 会话密钥
    """
    # 这里简单模拟共享密钥的获取，实际中需要使用正确的椭圆曲线算法
    shared_secret = compute_shared_secret(privkey_a,pubkey_b)  # 实际中需要使用真实的共享密钥计算
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'nip44-v2',
        info=b'',
        backend=default_backend()
    )
    return hkdf._extract(shared_secret)

def get_message_keys(conversation_key: bytes, nonce: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    获取消息密钥
    :param conversation_key: 会话密钥
    :param nonce: 随机数
    :return: chacha密钥，chacha非ce，hmac密钥
    """
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=76,
        info=nonce,
        backend=default_backend()
    )
    keys = hkdf.derive(conversation_key)
    chacha_key = keys[:32]
    chacha_nonce = keys[32:44]
    hmac_key = keys[44:]
    return chacha_key, chacha_nonce, hmac_key

def calc_padded_len(length: int) -> int:
    """
    计算填充后的长度
    :param length: 原始长度
    :return: 填充后的长度
    """
    if not isinstance(length, int) or length < 1:
        raise ValueError('expected positive integer')
    if length <= 32:
        return 32
    next_power = 1 << (length - 1).bit_length()
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((length - 1) // chunk + 1)

def write_u16be(num: int) -> bytes:
    """
    将整数转换为大端序的16位字节数组
    :param num: 整数
    :return: 大端序的16位字节数组
    """
    if not isinstance(num, int) or num < MIN_PLAINTEXT_SIZE or num > MAX_PLAINTEXT_SIZE:
        raise ValueError('invalid plaintext size: must be between 1 and 65535 bytes')
    return num.to_bytes(2, byteorder='big')

def pad(plaintext: str) -> bytes:
    """
    填充明文
    :param plaintext: 明文
    :return: 填充后的字节数组
    """
    unpadded = plaintext.encode('utf-8')
    unpadded_len = len(unpadded)
    prefix = write_u16be(unpadded_len)
    suffix = bytes(calc_padded_len(unpadded_len) - unpadded_len)
    return prefix + unpadded + suffix

def unpad(padded: bytes) -> str:
    """
    去除填充
    :param padded: 填充后的字节数组
    :return: 原始明文
    """
    unpadded_len = int.from_bytes(padded[:2], byteorder='big')
    unpadded = padded[2:2 + unpadded_len]
    if (
        unpadded_len < MIN_PLAINTEXT_SIZE or
        unpadded_len > MAX_PLAINTEXT_SIZE or
        len(unpadded) != unpadded_len or
        len(padded) != 2 + calc_padded_len(unpadded_len)
    ):
        raise ValueError('invalid padding')
    return unpadded.decode('utf-8')

def hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
    """
    计算HMAC
    :param key: 密钥
    :param message: 消息
    :param aad: 附加数据
    :return: HMAC值
    """
    if len(aad) != 32:
        raise ValueError('AAD associated data must be 32 bytes')
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(aad + message)
    return h.finalize()

def decode_payload(payload: str) -> Tuple[bytes, bytes, bytes]:
    """
    解码负载
    :param payload: 负载字符串
    :return: 随机数，密文，MAC
    """
    if not isinstance(payload, str):
        raise ValueError('payload must be a valid string')
    plen = len(payload)
    if plen < 132 or plen > 87472:
        raise ValueError(f'invalid payload length: {plen}')
    if payload[0] == '#':
        raise ValueError('unknown encryption version')
    try:
        data = base64.b64decode(payload)
    except Exception as e:
        raise ValueError(f'invalid base64: {str(e)}')
    dlen = len(data)
    if dlen < 99 or dlen > 65603:
        raise ValueError(f'invalid data length: {dlen}')
    vers = data[0]
    if vers != 2:
        raise ValueError(f'unknown encryption version {vers}')
    nonce = data[1:33]
    ciphertext = data[33:-32]
    mac = data[-32:]
    return nonce, ciphertext, mac

def encrypt(plaintext: str, conversation_key: bytes, nonce: bytes = os.urandom(32)) -> str:
    """
    加密明文
    :param plaintext: 明文
    :param conversation_key: 会话密钥
    :param nonce: 随机数
    :return: 加密后的字符串
    """
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    padded = pad(plaintext)
    
    encryptor = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    ciphertext = encryptor.encrypt(padded) 
    mac = hmac_aad(hmac_key, ciphertext, nonce)
    return base64.b64encode(b'\x02' + nonce + ciphertext + mac).decode('utf-8')

def decrypt(payload: str, conversation_key: bytes) -> str:
    """
    解密密文
    :param payload: 密文
    :param conversation_key: 会话密钥
    :return: 解密后的明文
    """
    nonce, ciphertext, mac = decode_payload(payload)
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
 
    calculated_mac = hmac_aad(hmac_key, ciphertext, nonce)
    if calculated_mac != mac:
        raise ValueError('invalid MAC')

    cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext) 

# 示例使用
if False :
    privkey_a  = ''
    pubkey_b   = ''
    conversation_key = get_conversation_key(privkey_a, pubkey_b)

    nonce = b' '
    plaintext = ''
  
    encrypted = encrypt(plaintext,conversation_key,nonce)
     
    content = ''
    decrypted = decrypt(content, conversation_key)
     
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
