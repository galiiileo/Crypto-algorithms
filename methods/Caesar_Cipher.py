alphabet = "abcdefghijklmnopqrstuvwxyz"

def encryption(plaintext, key):
    ciphertext = ""
    for p_ch in plaintext.lower():
        if p_ch in alphabet:
            p_index = alphabet.index(p_ch)
            c_val = (p_index + key) % 26
            ciphertext += alphabet[c_val]
        else:
            ciphertext += p_ch
    return ciphertext

def decryption(ciphertext, key):
    plaintext = ""
    for c_ch in ciphertext.lower():
        if c_ch in alphabet:
            c_index = alphabet.index(c_ch)
            c_val = (c_index - key) % 26
            plaintext += alphabet[c_val]
        else:
            plaintext += c_ch
    return plaintext

def brute_force_decrypt(ciphertext):
    results = []
    for key in range(1, 26):
        results.append(f"Key {key}: {decryption(ciphertext, key)}")
    return "\n".join(results)