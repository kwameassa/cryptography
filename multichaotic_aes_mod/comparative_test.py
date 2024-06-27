from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from datetime import datetime
import os


def standard_aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext


def standard_aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    data = cipher.decrypt(ciphertext)
    return data


def generate_chen_chaotic_values(x, y, z, sigma, rho, beta):
    dx = sigma * (y - x)
    dy = rho * x - y - x * z
    dz = x * y - beta * z

    x += dx
    y += dy
    z += dz

    return x, y, z


def multi_chaotic_aes_key_expansion(master_key, rounds, sigma, rho, beta):
    key_expansion = []

    x, y, z = master_key[0], master_key[1], master_key[2]

    for _ in range(rounds):
        x, y, z = generate_chen_chaotic_values(x, y, z, sigma, rho, beta)
        key_expansion.append((x, y, z))

    return key_expansion


def multi_chaotic_aes_encrypt(data, key, rounds, sigma, rho, beta):
    key_expansion = multi_chaotic_aes_key_expansion(key, rounds, sigma, rho, beta)
    # Generate the key stream
    key_stream = b"".join(bytes([int(round_key[i]) % 256 for i in range(3)]) for round_key in key_expansion)

    cipher = AES.new(key_stream, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return ciphertext


def multi_chaotic_aes_decrypt(ciphertext, key, rounds, sigma, rho, beta):
    key_expansion = multi_chaotic_aes_key_expansion(key, rounds, sigma, rho, beta)
    key_stream = b"".join(bytes([round_key[i] for i in range(3)]) for round_key in key_expansion)

    cipher = AES.new(key_stream, AES.MODE_EAX)
    data = cipher.decrypt(ciphertext)

    return data


def generate_key():
    return get_random_bytes(16)  # AES-128 key size


def save_file(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)


def load_file(filename):
    with open(filename, 'rb') as file:
        return file.read()


def main():
    # Accept file path from user
    file_path = input("Enter the path to the file: ")

    # Check if the file exists
    if not os.path.isfile(file_path):
        print("File not found.")
        return

    # Generate Key
    key = generate_key()

    # Load file data
    data = load_file(file_path)

    # Standard AES Encryption
    start_time = datetime.now()
    standard_aes_ciphertext = standard_aes_encrypt(data, key)
    standard_aes_encryption_time = datetime.now() - start_time

    # Save Encrypted File
    save_file(standard_aes_ciphertext, '../standard_aes_encrypted.bin')

    # MultiChaotic AES Encryption
    start_time = datetime.now()
    multi_chaotic_aes_ciphertext = multi_chaotic_aes_encrypt(data, key, rounds=10, sigma=1.0, rho=5.0, beta=0.1)  # Set the desired values for sigma, rho, and beta
    multi_chaotic_aes_encryption_time = datetime.now() - start_time

    # Save Encrypted File
    save_file(multi_chaotic_aes_ciphertext, 'multi_chaotic_aes_encrypted.bin')

    # Print Encryption Times
    print(f"Standard AES Encryption Time: {standard_aes_encryption_time}")
    print(f"MultiChaotic AES Encryption Time: {multi_chaotic_aes_encryption_time}")

    # Standard AES Decryption
    start_time = datetime.now()
    standard_aes_decrypted_data = standard_aes_decrypt(standard_aes_ciphertext, key)
    standard_aes_decryption_time = datetime.now() - start_time

    # Save Decrypted File
    save_file(standard_aes_decrypted_data, 'standard_aes_decrypted.txt')

    # MultiChaotic AES Decryption
    start_time = datetime.now()
    multi_chaotic_aes_decrypted_data = multi_chaotic_aes_decrypt(multi_chaotic_aes_ciphertext, key, rounds=10)
    multi_chaotic_aes_decryption_time = datetime.now() - start_time

    # Save Decrypted File
    save_file(multi_chaotic_aes_decrypted_data, 'multi_chaotic_aes_decrypted.txt')

    # Print Decryption Times
    print(f"Standard AES Decryption Time: {standard_aes_decryption_time}")
    print(f"MultiChaotic AES Decryption Time: {multi_chaotic_aes_decryption_time}")


if __name__ == "__main__":
    main()
