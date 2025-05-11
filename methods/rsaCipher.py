def modinv(a, m):
    """Extended Euclidean Algorithm for finding modular inverse"""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys():
    """Generate simple RSA keys (fixed primes for demo)"""
    p = 61
    q = 53
    n = p * q             # n = 3233
    phi = (p - 1) * (q - 1)  # φ(n) = 3120
    e = 17  # Public exponent
    d = modinv(e, phi)    # Private key
    
    return (e, n), (d, n)  # (public, private)

def encrypt(plaintext, public_key):
    """Simple RSA encryption"""
    e, n = public_key
    return [pow(ord(char), e, n) for char in plaintext]

def decrypt(ciphertext, private_key):
    """Simple RSA decryption"""
    d, n = private_key
    return ''.join([chr(pow(c, d, n)) for c in ciphertext])

def cipher_to_str(cipher):
    """Convert cipher list to string representation"""
    return ' '.join(map(str, cipher))

def str_to_cipher(s):
    """Convert string back to cipher list"""
    return [int(num) for num in s.split()]