import pyDes

def encrypt(plaintext, key):
    """DES Encryption with CBC mode and PKCS5 padding"""
    try:
        # Key must be exactly 8 bytes
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 characters long")
        des = pyDes.des(key, pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        encrypted_data = des.encrypt(plaintext)
        return encrypted_data
    except Exception as e:
        raise ValueError(f"DES encryption failed: {str(e)}")

def decrypt(ciphertext, key):
    """DES Decryption with CBC mode and PKCS5 padding"""
    try:
        # Key must be exactly 8 bytes
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 characters long")
        des = pyDes.des(key, pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        decrypted_data = des.decrypt(ciphertext)
        return decrypted_data.decode('utf-8')  
    except Exception as e:
        raise ValueError(f"DES decryption failed: {str(e)}")