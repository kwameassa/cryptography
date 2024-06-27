from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Function to convert bytes to a binary string
def bytes_to_binary_string(byte_data):
    return ''.join(format(byte, '08b') for byte in byte_data)

# Sample plaintext (must be a multiple of the block size or padded)
plaintext = b'This is a test message for AES encryption.'

# AES key (must be 16, 24, or 32 bytes long)
key = os.urandom(32)  # 256-bit key for AES-256

# Generate a random IV (Initialization Vector)
iv = os.urandom(16)

# Pad the plaintext to be a multiple of the block size (16 bytes for AES)
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_plaintext = padder.update(plaintext) + padder.finalize()

# Create a Cipher object
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

# Encrypt the padded plaintext
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

# Convert the ciphertext to a binary sequence
binary_sequence = bytes_to_binary_string(ciphertext)

print(f"Binary sequence: {binary_sequence}")
