alphabet = "abcdefghijklmnopqrstuvwxyz"

def generate_key(text, key):
    """Generate a key of appropriate length for the alphabetic characters in text"""
    # Filter only alphabetic characters from text to determine key length needed
    alpha_chars = [c for c in text.lower() if c in alphabet]
    alpha_key = [c for c in key.lower() if c in alphabet]
    
    if not alpha_key:
        raise ValueError("Key must contain at least one English letter")
    
    needed_length = len(alpha_chars)
    if needed_length == 0:
        return ""
    
    if len(alpha_key) == needed_length:
        return "".join(alpha_key)
    elif len(alpha_key) > needed_length:
        return "".join(alpha_key[:needed_length])
    else:
        # Extend the key to match the needed length
        extended_key = alpha_key.copy()
        for i in range(needed_length - len(alpha_key)):
            extended_key.append(alpha_key[i % len(alpha_key)])
        return "".join(extended_key)

def encryption(text, key):
    """Encrypt text using Vigenère cipher while preserving non-alphabetic characters"""
    ciphertext = []
    try:
        # Generate key based only on alphabetic characters
        effective_key = generate_key(text, key)
        print(f"Generated key for alphabetic chars: {effective_key}")
        
        key_ptr = 0
        for char in text:
            lower_char = char.lower()
            if lower_char in alphabet:
                # Only encrypt alphabetic characters
                p_value = alphabet.index(lower_char)
                k_value = alphabet.index(effective_key[key_ptr])
                c_value = (p_value + k_value) % 26
                ciphertext.append(alphabet[c_value])
                key_ptr += 1
            else:
                # Preserve non-alphabetic characters as-is
                ciphertext.append(char)
        return "".join(ciphertext)
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decryption(ciphertext, key):
    """Decrypt text using Vigenère cipher while preserving non-alphabetic characters"""
    plaintext = []
    try:
        # Generate key based only on alphabetic characters
        effective_key = generate_key(ciphertext, key)
        
        key_ptr = 0
        for char in ciphertext:
            lower_char = char.lower()
            if lower_char in alphabet:
                # Only decrypt alphabetic characters
                c_value = alphabet.index(lower_char)
                k_value = alphabet.index(effective_key[key_ptr])
                p_value = (c_value - k_value) % 26
                plaintext.append(alphabet[p_value])
                key_ptr += 1
            else:
                # Preserve non-alphabetic characters as-is
                plaintext.append(char)
        return "".join(plaintext)
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")