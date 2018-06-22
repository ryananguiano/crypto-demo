#!/usr/bin/env python
"""
PyCrypto Demo JSON Payload Encrypt/Decrypt

Ryan Anguiano
"""
import base64
import typing

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random


def generate_key_pair(size: int=1024) -> typing.Tuple[str, str]:
    """Generate a private/public RSA key pair"""
    key = RSA.generate(size)
    private_key = key.exportKey().decode('ascii')
    public_key = key.publickey().exportKey().decode('ascii')
    return private_key, public_key


def load_rsa_key(key: str) -> RSA._RSAobj:
    return RSA.importKey(key)


def generate_session_key(size: int=32) -> bytes:  # 32 bytes --> AES-256
    return Random.get_random_bytes(size)


def encrypt_session_key(public_key: str, session_key: bytes) -> bytes:
    rsa_key = load_rsa_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(session_key)


def decrypt_session_key(private_key: str, encrypted_key: bytes) -> bytes:
    rsa_key = load_rsa_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_key)


def encrypt_data(session_key: bytes, data: str) -> bytes:
    iv = session_key[:AES.block_size]
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return cipher_aes.encrypt(data.encode('utf8'))


def decrypt_data(session_key: bytes, data: bytes) -> str:
    iv = session_key[:AES.block_size]
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return cipher_aes.decrypt(data).decode('utf8')


def to_base64(value: bytes) -> str:
    return base64.b64encode(value).decode('ascii')


def from_base64(value: str) -> bytes:
    return base64.b64decode(value.encode('ascii'))


def encrypt_payload(public_key: str, data: str) -> typing.Mapping[str, str]:
    """Generate and encrypt a session key, and return with the encrypted data"""
    session_key = generate_session_key()
    encrypted_key = encrypt_session_key(public_key, session_key)
    encrypted_data = encrypt_data(session_key, data)
    return {
        'key': to_base64(encrypted_key),
        'payload': to_base64(encrypted_data),
    }


def decrypt_payload(private_key: str, payload: typing.Mapping[str, str]) -> str:
    """Decrypt the session key, then decrypt the payload and return the data"""
    encrypted_key = from_base64(payload['key'])
    encrypted_data = from_base64(payload['payload'])
    session_key = decrypt_session_key(private_key, encrypted_key)
    return decrypt_data(session_key, encrypted_data)


if __name__ == '__main__':
    print('Generating RSA Key Pair')
    private_key, public_key = generate_key_pair()
    
    print('\nPrivate Key:')
    print(private_key)
    print('\nPublic Key:')
    print(public_key)
    
    data = '{"foo":"bar","success":true}'
    
    payload = encrypt_payload(public_key, data)
    
    print('\nPayload:')
    print(payload)
    
    print('\nDecrypted Data:')
    print(decrypt_payload(private_key, payload))
