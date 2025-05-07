import math

def encrypt(plaintext, key):
    
    rows = math.ceil(len(plaintext) / len(key))
    matrix = [['_' for _ in range(len(key))] for _ in range(rows)]
    for index, char in enumerate(plaintext):
        row = int(index / len(key))
        col = index % len(key)
        matrix[row][col] = char
    sorted_key = sorted(key)
    ciphertext = ""
    for char in sorted_key:
        col = key.index(char)
        for row in range(rows):
            ciphertext += matrix[row][col]
    
    return ciphertext

def decrypt(ciphertext, key):
    rows = math.ceil(len(ciphertext) / len(key))
    matrix = [['_' for _ in range(len(key))] for _ in range(rows)]
    sorted_key = sorted((char, i) for i, char in enumerate(key))
    column_order = [i for char, i in sorted_key]
    
    index = 0
    for col in column_order:
        for row in range(rows):
            if index < len(ciphertext):
                matrix[row][col] = ciphertext[index]
                index += 1
    plaintext = ""
    for i in range(rows):
        for j in range(len(key)):
            plaintext += matrix[i][j]
    plaintext = plaintext.rstrip('_')
    return plaintext