import os
import hmac
import hashlib
from cryptography.fernet import Fernet # type: ignore


def generate_salt():
    """
    生成盐 generate salt
    """
    return os.urandom(16)


def hash_password(password, salt):
    """
    使用SHA-256哈希算法加盐加密密码
    """

    salted_password = password.encode('utf-8') + salt

    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password


def verify_password(stored_password, input_password, salt):
    """
    验证密码是否匹配
    """
    rehashed_password = hash_password(input_password, salt)
    return rehashed_password == stored_password


def generate_key():
    """
    生成对称加密密钥
    """
    return Fernet.generate_key()


def encrypt_message(message, key):
    """
    使用对称加密算法AES加密消息
    """
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message


def decrypt_message(encrypted_message, key):
    """
    使用对称加密算法AES解密消息
    """
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message


def generate_mac(message, key):
    """
    生成消息的HMAC签名
    """
    h = hmac.new(key, message, hashlib.sha256)
    return h.digest()


def verify_mac(message, mac, key):
    """
    验证消息的HMAC签名
    """
    expected_mac = generate_mac(message, key)
    return hmac.compare_digest(expected_mac, mac)

if __name__ == '__main__':

    # 生成密钥
    key = generate_key()

    # 要发送的消息
    message = "Hello, World!"

    # 加密消息
    encrypted_message = encrypt_message(message, key)
    print("加密后的消息:", encrypted_message)

    # 生成消息的 MAC
    mac = generate_mac(encrypted_message, key)
    print("MAC:", mac)

    # 假设消息被篡改
    tampered_message = encrypted_message + b'Tampered'

    # 验证 MAC
    is_valid = verify_mac(tampered_message, mac, key)
    if is_valid:
        print("消息完整性验证通过，消息未被篡改")
    else:
        print("消息完整性验证失败，消息可能已被篡改")

    # 解密消息
    decrypted_message = decrypt_message(encrypted_message, key)
    print("解密后的消息:", decrypted_message)
