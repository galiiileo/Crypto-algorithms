import onetimepad

def encrypt(plaintext , key):
    return onetimepad.encrypt(plaintext, key)

def decrypt(ciphertext , key):
    return onetimepad.decrypt(ciphertext, key)
