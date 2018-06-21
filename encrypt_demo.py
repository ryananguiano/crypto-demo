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
    """Generates a private/public RSA key pairs"""
    key = RSA.generate(size)
    private_key = key.exportKey()
    public_key = key.publickey().exportKey()
    return private_key, public_key


def load_key(key: str) -> RSA._RSAobj:
    return RSA.importKey(key)


def generate_session_key(size=32) -> bytes:
    return Random.get_random_bytes(size)


def encrypt_session_key(public_key: str, session_key: bytes) -> bytes:
    key = load_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    return cipher_rsa.encrypt(session_key)


def decrypt_session_key(private_key: str, encrypted_key: bytes) -> bytes:
    key = load_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    return cipher_rsa.decrypt(encrypted_key)


def encrypt_data(session_key: bytes, data: str) -> bytes:
    iv = session_key[:AES.block_size]
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return cipher_aes.encrypt(data)


def decrypt_data(session_key: bytes, data: bytes) -> str:
    iv = session_key[:AES.block_size]
    cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
    return cipher_aes.decrypt(data)


def encrypt_payload(public_key: str, data: str) -> typing.Mapping[str, str]:
    """Generate and encrypt a session key, and return with the encrypted data"""
    session_key = generate_session_key()
    encrypted_key = encrypt_session_key(public_key, session_key)
    encrypted_data = encrypt_data(session_key, data)
    return {
        'key': base64.b64encode(encrypted_key),
        'payload': base64.b64encode(encrypted_data),
    }


def decrypt_payload(private_key: str, payload: typing.Mapping[str, str]) -> str:
    """Decrypts the session key, then decrypts the payload and returns the data"""
    encrypted_key = base64.b64decode(payload['key'])
    encrypted_data = base64.b64decode(payload['payload'])
    session_key = decrypt_session_key(private_key, encrypted_key)
    return decrypt_data(session_key, encrypted_data)


if __name__ == '__main__':
    private_key, public_key = generate_key_pair()
    
    print('Private Key:')
    print(private_key)
    print('\nPublic Key:')
    print(public_key)
    
    data = '{"foo":"bar","success":true}'
    
    payload = encrypt_payload(public_key, data)
    
    print('\nPayload:')
    print(payload)
    
    print('\nDecrypted Data:')
    print(decrypt_payload(private_key, payload))
