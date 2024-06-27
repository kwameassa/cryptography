import secrets
import time
import random
import string
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Simulated email sender and receiver
sender_email = "sender@example.com"
receiver_email = "receiver@example.com"

def generate_random_message(length=100):
    """Generate a random email message."""
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def generate_rsa_key_pair():
    """Generate RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_signature(private_key, data):
    """Generate a digital signature for the data."""
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, data, signature):
    """Verify the digital signature of the data."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


def generate_symmetric_key():
    """Generate a random symmetric encryption key."""
    return secrets.token_bytes(32)  # 256 bits


def encrypt_symmetric_key(symmetric_key, public_key):
    """Encrypt the symmetric key with RSA."""
    ciphertext = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_symmetric_key(ciphertext, private_key):
    """Decrypt the symmetric key with RSA."""
    symmetric_key = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symmetric_key

def encrypt_message(message, symmetric_key):
    """Encrypt a message with AES-GCM."""
    # Generate a random IV (Initialization Vector)
    iv = secrets.token_bytes(16)  # 128 bits
    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag

def decrypt_message(ciphertext, symmetric_key):
    """Decrypt a message with AES-GCM."""
    iv = ciphertext[:16]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[16:-16]
    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def simulate_secure_email():
    print("Simulating a Secure Email Transaction...")

    # Simulate key exchange time
    start_time = time.time()
    sender_private_key, receiver_public_key = generate_rsa_key_pair()
    key_exchange_time = time.time() - start_time
    print(f"Key Exchange Time: {key_exchange_time:.6f} seconds")

    # Prompt user for email message file
    file_path = input("Enter the path of the email message file: ")

    try:
        with open(file_path, 'rb') as file:  # Open in binary mode
            message = file.read()
    except FileNotFoundError:
        print("File not found. Please provide a valid file path.")
        return

    # Generate a random symmetric key
    symmetric_key = generate_symmetric_key()

    # Encrypt the symmetric key with the recipient's public key
    symmetric_key_ciphertext = encrypt_symmetric_key(symmetric_key, receiver_public_key)

    # Generate a digital signature for the email
    start_time = time.time()
    signature = generate_signature(sender_private_key, message)
    signature_generation_time = time.time() - start_time
    print(f"Signature Generation Time: {signature_generation_time:.6f} seconds")

    # Encrypt the email message with the symmetric key
    start_time = time.time()
    ciphertext = encrypt_message(message, symmetric_key)
    encryption_time = time.time() - start_time
    print(f"Encryption Time: {encryption_time:.6f} seconds")

    print("Email sent securely.")

    # Simulate email reception

    # Decrypt the symmetric key with the recipient's private key
    symmetric_key_received = decrypt_symmetric_key(symmetric_key_ciphertext, sender_private_key)

    # Verify the digital signature
    start_time = time.time()
    signature_valid = verify_signature(sender_private_key.public_key(), message, signature)
    signature_verification_time = time.time() - start_time

    if signature_valid:
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")

    # Decrypt the email message with the symmetric key
    start_time = time.time()
    decrypted_message = decrypt_message(ciphertext, symmetric_key_received)
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
