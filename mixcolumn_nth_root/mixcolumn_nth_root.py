import numpy as np
import time
import os

# AES MixColumns constants
MIX_COLUMN_MATRIX = np.array([
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
], dtype=np.uint8)

INVERSE_MIX_COLUMN_MATRIX = np.array([
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
], dtype=np.uint8)

# Function to apply Nth Root Function to each element in the matrix
def applyNthRootFunction(matrix, N):
    return np.power(matrix, 1 / N)

# Function to perform Mix Column with Nth Root modification
def mixColumn(matrix, N, inverse=False):
    # Apply Nth Root Function
    matrix = applyNthRootFunction(matrix, N)

    # Select the appropriate mix column matrix based on inverse flag
    mix_column_matrix = INVERSE_MIX_COLUMN_MATRIX if inverse else MIX_COLUMN_MATRIX

    # Perform MixColumns operation
    result = np.zeros_like(matrix, dtype=np.float64)
    for col in range(4):
        for row in range(4):
            result[row, col] = np.sum(mix_column_matrix[row, :] * matrix[:, col]) % 256

    return result

# Function to encrypt data using the modified Mix Column
def encrypt_data(data, N):
    # Reshape data into a 4x4 matrix (assuming AES block size)
    matrix = data.reshape(4, 4)

    # Encrypt using modified Mix Column
    encrypted_matrix = mixColumn(matrix, N)

    # Flatten the matrix back to a 1D array
    encrypted_data = encrypted_matrix.flatten().astype(np.uint8)

    return encrypted_data

# Function to decrypt data using the modified Mix Column
def decrypt_data(data, N):
    # Reshape data into a 4x4 matrix (assuming AES block size)
    matrix = data.reshape(4, 4)

    # Decrypt using modified Mix Column (inverse operation)
    decrypted_matrix = mixColumn(matrix, N, inverse=True)

    # Flatten the matrix back to a 1D array
    decrypted_data = decrypted_matrix.flatten().astype(np.uint8)

    return decrypted_data

# Function to process the file input
def process_file(file_path, N, operation='encrypt'):
    # Read the file
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Ensure the data length is a multiple of 16 bytes
    padding_length = 0
    if len(file_data) % 16 != 0:
        padding_length = 16 - (len(file_data) % 16)
        file_data = np.pad(np.frombuffer(file_data, dtype=np.uint8), (0, padding_length), 'constant')
    else:
        file_data = np.frombuffer(file_data, dtype=np.uint8)

    # Process each 16-byte block
    processed_data = bytearray()
    for i in range(0, len(file_data), 16):
        block = file_data[i:i + 16]
        if operation == 'encrypt':
            processed_block = encrypt_data(block, N)
        else:
            processed_block = decrypt_data(block, N)
        processed_data.extend(processed_block)

    # Remove padding for decryption
    if operation == 'decrypt' and padding_length != 0:
        processed_data = processed_data[:-padding_length]

    # Save the processed file
    output_file_path = os.path.join(os.path.dirname(file_path), f"{operation}_output_{os.path.basename(file_path)}")
    with open(output_file_path, 'wb') as output_file:
        output_file.write(processed_data)

    print(f"{operation.capitalize()}ed file saved as: {output_file_path}")

    return output_file_path

# Main function
def main():
    file_path = input("Enter the path to the file: ")
    N = 3  # You can modify this value as needed

    start_time = time.time()
    encrypted_file = process_file(file_path, N, 'encrypt')
    decrypted_file = process_file(encrypted_file, N, 'decrypt')
    end_time = time.time()

    print(f"Processing time: {end_time - start_time} seconds")
    print(f"Decrypted file saved as: {decrypted_file}")

if __name__ == "__main__":
    main()
