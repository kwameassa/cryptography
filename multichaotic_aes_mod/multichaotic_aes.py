from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import time

# Lorenz attractor step function
def lorenz_step(x, y, z, sigma, rho, beta, dt=0.01):
    dx = sigma * (y - x) * dt
    dy = (x * (rho - z) - y) * dt
    dz = (x * y - beta * z) * dt
    return x + dx, y + dy, z + dz

# Chen attractor step function
def chen_step(x, y, z, alpha, beta, delta, dt=0.01):
    dx = alpha * (y - x) * dt
    dy = (beta * x - y - x * z) * dt
    dz = (delta * z + x * y - z) * dt
    return x + dx, y + dy, z + dz

# Multi-chaotic key expansion
def multi_chaotic_key_expansion(key, rounds, lorenz_params, chen_params):
    sigma, rho, beta = lorenz_params
    alpha, chen_beta, delta = chen_params
    x, y, z = key[:3]
    key_stream = []

    for _ in range(rounds):
        x, y, z = lorenz_step(x, y, z, sigma, rho, beta)
        x, y, z = chen_step(x, y, z, alpha, chen_beta, delta)

        # Cap values to prevent overflow
        if abs(x) > 1e6: x = 1e6 * (x / abs(x))
        if abs(y) > 1e6: y = 1e6 * (y / abs(y))
        if abs(z) > 1e6: z = 1e6 * (z / abs(z))

        key_stream.append(x)
        key_stream.append(y)
        key_stream.append(z)

    key_stream = [min(max(int(abs(k) * 10 ** 6) % 256, 0), 255) for k in key_stream]

    return bytes(key_stream[:32])  # Ensure the key is 32 bytes long

# Multi-chaotic AES encryption
def multi_chaotic_aes_encrypt(data, key, rounds, lorenz_params, chen_params):
    key_stream = multi_chaotic_key_expansion(key, rounds, lorenz_params, chen_params)
    cipher = AES.new(key_stream[:16], AES.MODE_EAX)
    nonce = cipher.nonce
    start_time = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end_time = time.time()
    encryption_time = end_time - start_time
    return nonce + ciphertext, encryption_time

# Multi-chaotic AES decryption
def multi_chaotic_aes_decrypt(ciphertext, key, rounds, lorenz_params, chen_params):
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]
    key_stream = multi_chaotic_key_expansion(key, rounds, lorenz_params, chen_params)
    cipher = AES.new(key_stream[:16], AES.MODE_EAX, nonce=nonce)
    start_time = time.time()
    data = cipher.decrypt(ciphertext)
    end_time = time.time()
    decryption_time = end_time - start_time
    return data, decryption_time

# Function to generate a key of appropriate length
def generate_key(bit_size):
    return get_random_bytes(bit_size // 8)  # Generate a key based on the bit size

# Function to save binary data to a file
def save_file(filepath, data):
    with open(filepath, 'wb') as file:
        file.write(data)

# Function to load binary data from a file
def load_file(filepath):
    with open(filepath, 'rb') as file:
        return file.read()

def main():
    input_file_path = input("Enter the path of the file to encrypt: ")
    key_bit_size = int(input("Enter the key bit size (128, 192, 256): "))

    # Ensure the key bit size is one of the valid options
    if key_bit_size not in [128, 192, 256]:
        print("Invalid key bit size. Please enter 128, 192, or 256.")
        return

    # Extract directory and filename from the input path
    file_dir = os.path.dirname(input_file_path)
    file_name = os.path.basename(input_file_path)
    file_base_name, file_ext = os.path.splitext(file_name)

    # Define output file paths
    output_encrypted_file_path = os.path.join(file_dir, f"{file_base_name}_encrypted{file_ext}")
    output_decrypted_file_path = os.path.join(file_dir, f"{file_base_name}_decrypted{file_ext}")

    data = load_file(input_file_path)
    key = generate_key(key_bit_size)

    # Parameters for Lorenz and Chen attractors
    rounds = 10
    lorenz_params = (10.0, 28.0, 8.0 / 3.0)
    chen_params = (35.0, 3.0, 28.0)

    # Encrypt the data
    encrypted_data, encryption_time = multi_chaotic_aes_encrypt(pad(data, AES.block_size), key, rounds, lorenz_params, chen_params)
    save_file(output_encrypted_file_path, encrypted_data)
    print(f"Encrypted data saved to {output_encrypted_file_path}")
    print(f"Encryption time: {encryption_time:.6f} seconds")

    # Decrypt the data
    decrypted_data, decryption_time = multi_chaotic_aes_decrypt(encrypted_data, key, rounds, lorenz_params, chen_params)
    decrypted_data = unpad(decrypted_data, AES.block_size)
    save_file(output_decrypted_file_path, decrypted_data)
    print(f"Decrypted data saved to {output_decrypted_file_path}")
    print(f"Decryption time: {decryption_time:.6f} seconds")

if __name__ == "__main__":
    main()
