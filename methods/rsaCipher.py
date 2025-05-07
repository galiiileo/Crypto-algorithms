from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def generate_keys(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt(plaintext, public_key):
    try:
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted = cipher.encrypt(plaintext.encode())
        return binascii.hexlify(encrypted).decode()
    except Exception as e:
        raise ValueError(f"RSA encryption failed: {str(e)}")

def decrypt(ciphertext, private_key):
    try:
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted = cipher.decrypt(binascii.unhexlify(ciphertext))
        return decrypted.decode()
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {str(e)}")