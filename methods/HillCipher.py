import numpy as np

def text_to_numbers(text):
    return [ord(c.upper()) - ord('A') for c in text if c.isalpha()]

def numbers_to_text(numbers):
    return ''.join(chr(n + ord('A')) for n in numbers)

def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inv(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix))) % modulus
    det_inv = mod_inverse(det, modulus)
    if det_inv is None:
        raise ValueError("Matrix is not invertible.")
    inv_matrix = np.array([[matrix[1,1], -matrix[0,1]],
                        [-matrix[1,0], matrix[0,0]]])
    return (det_inv * inv_matrix) % modulus

def encrypt(plaintext, key_matrix):
    numbers = text_to_numbers(plaintext)
    if len(numbers) % 2 != 0:
        numbers.append(ord('X') - ord('A'))
    ciphertext = []
    for i in range(0, len(numbers), 2):
        block = np.array([[numbers[i]], [numbers[i+1]]])
        encrypted_block = np.dot(key_matrix, block) % 26
        ciphertext.extend(encrypted_block.flatten())
    return numbers_to_text(ciphertext)

def decrypt(ciphertext,key_matrix):
    numbers = text_to_numbers(ciphertext)
    plaintext = []
    inv_matrix = matrix_mod_inv(key_matrix, 26)
    for i in range(0, len(numbers), 2):
        block = np.array([[numbers[i]], [numbers[i+1]]])
        decrypted_block = np.dot(inv_matrix, block) % 26
        plaintext.extend(decrypted_block.flatten())
    if plaintext[-1]==(ord('X')-ord('A')):
        plaintext=plaintext[:-1]
    return numbers_to_text(plaintext)