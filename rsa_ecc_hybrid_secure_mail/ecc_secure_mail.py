import secrets
import time
import random
import string
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Simulated email sender and receiver
sender_email = "sender@example.com"
receiver_email = "receiver@example.com"

def generate_random_message(length=100):
    """Generate a random email message."""
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def generate_ec_key_pair():
    """Generate ECC key pair."""
    private_key = ec.generate_private_key(
        ec.SECP224R1(),
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_signature(private_key, data):
    """Generate a digital signature for the data."""
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, data, signature):
    """Verify the digital signature of the data."""
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def generate_symmetric_key():
    """Generate a random symmetric encryption key."""
    return secrets.token_bytes(32)  # 256 bits

def derive_shared_secret(private_key, public_key):
    """Derive a shared secret from ECC key exchange."""
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    return shared_secret

def encrypt_message(message, symmetric_key):
    """Encrypt a message with AES-GCM."""
    iv = secrets.token_bytes(16)  # 128 bits
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag

def decrypt_message(ciphertext, symmetric_key):
    """Decrypt a message with AES-GCM."""
    iv = ciphertext[:16]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[16:-16]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def simulate_secure_email():
    print("Simulating a Secure Email Transaction...")

    start_time = time.time()
    sender_private_key, sender_public_key = generate_ec_key_pair()
    key_exchange_time = time.time() - start_time
    print(f"Key Exchange Time: {key_exchange_time:.6f} seconds")

    start_time = time.time()
    receiver_private_key, receiver_public_key = generate_ec_key_pair()
    key_exchange_time = time.time() - start_time
    print(f"Key Exchange Time: {key_exchange_time:.6f} seconds")

    file_path = input("Enter the path of the email message file: ")

    try:
        with open(file_path, 'rb') as file:
            message = file.read()
    except FileNotFoundError:
        print("File not found. Please provide a valid file path.")
        return

    shared_secret = derive_shared_secret(sender_private_key, receiver_public_key)
    symmetric_key = generate_symmetric_key()

    start_time = time.time()
    signature = generate_signature(sender_private_key, message)
    signature_generation_time = time.time() - start_time
    print(f"Signature Generation Time: {signature_generation_time:.6f} seconds")

    start_time = time.time()
    ciphertext = encrypt_message(message, symmetric_key)
    encryption_time = time.time() - start_time
    print(f"Encryption Time: {encryption_time:.6f} seconds")

    print("Email sent securely.")

    # Verify the digital signature
    start_time = time.time()
    signature_valid = verify_signature(sender_public_key, message, signature)
    signature_verification_time = time.time() - start_time

    if signature_valid:
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")

    start_time = time.time()
    decrypted_message = decrypt_message(ciphertext, symmetric_key)
    decryption_time = time.time() - start_time
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    print("Email received securely.")
    print("\nSummary:")
    print(f"Key Exchange Time: {key_exchange_time:.6f} seconds")
    print(f"Signature Generation Time: {signature_generation_time:.6f} seconds")
    print(f"Encryption Time: {encryption_time:.6f} seconds")
    print(f"Signature Verification Time: {signature_verification_time:.6f} seconds")
    print(f"Decryption Time: {decryption_time:.6f} seconds")

if __name__ == "__main__":
    simulate_secure_email()
