# Implementasi DES (Data Encryption Standard)

# Initial Permutation (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Initial Permutation (IP^-1)
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S-boxes (lengkap 8 S-boxes)
S_BOXES = [
    # S-box 1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    # S-box 2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    # S-box 3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    # S-box 4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    # S-box 5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    # S-box 6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    # S-box 7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    # S-box 8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ],
]

# Permutation function
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Key generation tables
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Number of left shifts for each round
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(block, table):
    return ''.join(block[i-1] for i in table)

def xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))

def left_shift(key, n):
    return key[n:] + key[:n]

def string_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def hex_to_bin(hex_str):
    return ''.join(format(int(c, 16), '04b') for c in hex_str)

def binary_to_string(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(char, 2)) for char in chars if int(char, 2) != 0)

def generate_subkeys(key):
    # Apply PC1 permutation
    key = permute(key, PC1)
    
    # Split into left and right halves
    left, right = key[:28], key[28:]
    
    subkeys = []
    for i in range(16):
        # Perform left shifts
        left = left_shift(left, SHIFT_SCHEDULE[i])
        right = left_shift(right, SHIFT_SCHEDULE[i])
        
        # Combine and apply PC2 permutation
        combined = left + right
        subkey = permute(combined, PC2)
        subkeys.append(subkey)
    
    return subkeys

def f_function(right_half, subkey):
    # Expansion
    expanded = permute(right_half, E)
    
    # XOR with subkey
    xored = xor(expanded, subkey)
    
    # S-box substitution
    output = ''
    for i in range(8):
        block = xored[i*6:(i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        sbox_value = S_BOXES[i][row][col]
        output += format(sbox_value, '04b')
    
    # Permutation
    return permute(output, P)

def des_round(left_half, right_half, subkey):
    temp = right_half
    right_half = xor(left_half, f_function(right_half, subkey))
    left_half = temp
    return left_half, right_half

def des_encrypt(plaintext, key_hex):
    # Convert plaintext to binary, pad if necessary
    plaintext_bin = string_to_binary(plaintext)
    if len(plaintext_bin) < 64:
        plaintext_bin = plaintext_bin.ljust(64, '0')
    elif len(plaintext_bin) > 64:
        plaintext_bin = plaintext_bin[:64]
    
    # Convert key from hex to binary
    key_bin = hex_to_bin(key_hex)
    if len(key_bin) < 64:
        key_bin = key_bin.zfill(64)
    elif len(key_bin) > 64:
        key_bin = key_bin[:64]
    
    # Generate subkeys
    subkeys = generate_subkeys(key_bin)
    
    # Initial permutation
    block = permute(plaintext_bin, IP)
    
    # Split into left and right halves
    left, right = block[:32], block[32:]
    
    # 16 rounds
    for i in range(16):
        left, right = des_round(left, right, subkeys[i])
    
    # Combine and apply final permutation
    combined = right + left
    ciphertext_bin = permute(combined, IP_INV)
    
    # Convert binary to hex
    ciphertext_hex = hex(int(ciphertext_bin, 2))[2:].upper()
    return ciphertext_hex.zfill(16)

def des_decrypt(ciphertext_hex, key_hex):
    # Convert ciphertext from hex to binary
    ciphertext_bin = bin(int(ciphertext_hex, 16))[2:].zfill(64)
    
    # Convert key from hex to binary
    key_bin = hex_to_bin(key_hex)
    if len(key_bin) < 64:
        key_bin = key_bin.zfill(64)
    elif len(key_bin) > 64:
        key_bin = key_bin[:64]
    
    # Generate subkeys
    subkeys = generate_subkeys(key_bin)
    
    # Initial permutation
    block = permute(ciphertext_bin, IP)
    
    # Split into left and right halves
    left, right = block[:32], block[32:]
    
    # 16 rounds (use subkeys in reverse order for decryption)
    for i in range(15, -1, -1):
        left, right = des_round(left, right, subkeys[i])
    
    # Combine and apply final permutation
    combined = right + left
    plaintext_bin = permute(combined, IP_INV)
    
    # Convert binary to string
    return binary_to_string(plaintext_bin)

# [Semua fungsi dan konstanta DES yang ada tetap sama]

def generate_key(seed):
    """Generate a pseudo-random 64-bit key in hexadecimal format."""
    hex_chars = "0123456789ABCDEF"
    key = ""
    for _ in range(16):
        # Using a simple Linear Congruential Generator
        seed = (seed * 1103515245 + 12345) & 0x7fffffff
        key += hex_chars[seed % 16]
    return key, seed

def pad_text(text):
    """Pad the text to be a multiple of 8 bytes."""
    padding_length = 8 - (len(text) % 8)
    return text + chr(padding_length) * padding_length

def unpad_text(text):
    """Remove the padding from the decrypted text."""
    padding_length = ord(text[-1])
    return text[:-padding_length]

def des_encrypt_with_padding(plaintext, key_hex):
    padded_plaintext = pad_text(plaintext)
    return des_encrypt(padded_plaintext, key_hex)

def des_decrypt_with_unpadding(ciphertext_hex, key_hex):
    decrypted_padded = des_decrypt(ciphertext_hex, key_hex)
    return unpad_text(decrypted_padded)

def format_output(key, plaintext, ciphertext, decrypted):
    return f"""
Key: {key}
Plaintext: {plaintext}
Ciphertext: {ciphertext}
Decrypted: {decrypted}
"""

# Example usage
if __name__ == "__main__":
    # Initialize seed for key generation
    seed = 12345  # You can change this to any initial value

    # Generate a pseudo-random key
    key_hex, new_seed = generate_key(seed)
    
    plaintext = "gianjayy"

    # Encrypt
    ciphertext = des_encrypt_with_padding(plaintext, key_hex)

    # Decrypt
    decrypted_text = des_decrypt_with_unpadding(ciphertext, key_hex)

    # Format and print output
    output = format_output(key_hex, plaintext, ciphertext, decrypted_text)
    print(output)

    # Optional: Write output to file
    with open('des_output.txt', 'w') as f:
        f.write(output)
    print("Output telah disimpan ke file 'des_output.txt'")