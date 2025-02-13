
import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import coincurve as secp256k1
from coincurve._libsecp256k1 import ffi,lib

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


def encrypt(message: str, private_key, public_key_hex: str) -> str:
    """
    对给定的消息进行加密。

    参数:
    message (str): 要加密的消息。
    private_key: 私钥对象。
    public_key_hex (str): 接收方的公钥（十六进制字符串）。

    返回:
    str: 加密后的消息，格式为 "加密内容?iv=初始化向量"。
    """
    # 使用PKCS7填充数据
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # 生成随机的初始化向量
    iv = secrets.token_bytes(16)

    # 创建加密器
    cipher = Cipher(
        algorithms.AES(compute_shared_secret(private_key, public_key_hex)), modes.CBC(iv)
    )
    encryptor = cipher.encryptor()

    # 执行加密操作
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

    # 对加密内容和初始化向量进行Base64编码
    ret_part1 = base64.b64encode(encrypted_message).decode()
    ret_part2 = base64.b64encode(iv).decode()

    return f"{ret_part1}?iv={ret_part2}"

def decrypt(encoded_message: str, private_key, public_key_hex: str) -> str:
    """
    对给定的加密消息进行解密。

    参数:
    encoded_message (str): 加密后的消息，格式为 "加密内容?iv=初始化向量"。
    private_key: 私钥对象。
    public_key_hex (str): 发送方的公钥（十六进制字符串）。

    返回:
    str: 解密后的消息。
    """
    # 分离加密内容和初始化向量
    encoded_data = encoded_message.split('?iv=')
    encoded_content, encoded_iv = encoded_data[0], encoded_data[1]

    # 对初始化向量进行Base64解码
    iv = base64.b64decode(encoded_iv)

    # 创建解密器
    cipher = Cipher(
        algorithms.AES(compute_shared_secret(private_key, public_key_hex)), modes.CBC(iv)
    )
    encrypted_content = base64.b64decode(encoded_content)

    # 执行解密操作
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_content) + decryptor.finalize()

    # 去除PKCS7填充
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_message) + unpadder.finalize()

    return unpadded_data.decode()


# 示例用法
if __name__ ==  '__main__':
    from . import key
    nprivkey = 'nsec....'
    privkey = key.PrivateKey(nprivkey)
    
    pubkey = '... '
    content = ' 4321432?iv=cEd+fdsa=='
    
    decrypted_message = decrypt(content,privkey.raw_secret, pubkey )
    print(f"Decrypted message: {decrypted_message}")
