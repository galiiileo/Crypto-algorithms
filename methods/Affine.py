from sympy import mod_inverse

alphabet = "abcdefghijklmnopqrstuvwxyz"
alphabet_size = len(alphabet)

def encrypt(plaintext, a, b):
    """Encrypt text using Affine cipher while preserving non-alphabetic characters"""
    ciphertext = []
    for char in plaintext:
        lower_char = char.lower()
        if lower_char in alphabet:
            p_index = alphabet.index(lower_char)
            c_val = (a * p_index + b) % alphabet_size
            ciphertext.append(alphabet[c_val])
        else:
            ciphertext.append(char)
    return ''.join(ciphertext)

def decrypt(ciphertext, a, b):
    """Decrypt text using Affine cipher while preserving non-alphabetic characters"""
    plaintext = []
    try:
        inv_a = mod_inverse(a, alphabet_size)
        for char in ciphertext:
            lower_char = char.lower()
            if lower_char in alphabet:
                c_index = alphabet.index(lower_char)
                p_val = (inv_a * (c_index - b)) % alphabet_size
                plaintext.append(alphabet[p_val])
            else:
                plaintext.append(char)
        return ''.join(plaintext)
    except ValueError:
        raise ValueError(f"No modular inverse exists for a={a} mod 26")

def get_valid_a_values():
    """Get all valid 'a' values that have modular inverse modulo 26"""
    valid = []
    for a in range(1, alphabet_size):  
        try:
            mod_inverse(a, alphabet_size)
            valid.append(a)
        except ValueError:
            continue
    return valid

