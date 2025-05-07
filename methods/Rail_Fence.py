def encrypt(plaintext, key):
    """Encrypt text using Rail Fence cipher"""
    plaintext = plaintext.replace(' ', '')
    ciphertext = [""] * key
    for row in range(key):
        pointer = row
        while pointer < len(plaintext):
            ciphertext[row] += plaintext[pointer]
            pointer += key
    return "".join(ciphertext)

def decrypt(ciphertext, key):
    """Decrypt text using Rail Fence cipher"""
    ciphertext = ciphertext.replace(' ', '')
    n = len(ciphertext)
    cols = n // key
    extra = n % key
    rows = []
    start = 0
    for i in range(key):
        end = start + cols + (1 if i < extra else 0)
        rows.append(ciphertext[start:end])
        start = end
    result = ''
    for i in range(len(rows[0])):
        for row in rows:
            if i < len(row):
                result += row[i]
    return result