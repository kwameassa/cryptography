import secrets
import time
import random
import string
from cryptography.hazmat.primitives import serialization
# import mail_server_conn
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Simulated email sender and receiver
sender_email = "sender@ec2-16-171-225-190.eu-north-1.compute.amazonaws.com"
receiver_email = "receiver@ec2-16-171-225-190.eu-north-1.compute.amazonaws.com"

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
        ec.ECDSA(hashes.SHA256())
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

def rsa_encrypt_symmetric_key(symmetric_key, public_key):
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

def rsa_decrypt_symmetric_key(ciphertext, private_key):
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

def simulate_hybrid_secure_email():
    print("Simulating a Hybrid Secure Email Transaction...")

    # Simulate key exchange time
    start_time = time.time()
    sender_ec_private, sender_ec_public = generate_ec_key_pair()
    key_exchange_time_ec = time.time() - start_time
    print(f"ECC Key Exchange Time: {key_exchange_time_ec:.6f} seconds")

    start_time = time.time()
    receiver_rsa_private, receiver_rsa_public = generate_rsa_key_pair()
    receiver_ec_private, receiver_ec_public = generate_ec_key_pair()
    key_exchange_time_rsa = time.time() - start_time
    print(f"RSA Key Exchange Time: {key_exchange_time_rsa:.6f} seconds")

    # Prompt user for email message file
    file_path = input("Enter the path of the email message file: ")

    try:
        with open(file_path, 'rb') as file:  # Open in binary mode
            message = file.read()
    except FileNotFoundError:
        print("File not found. Please provide a valid file path.")
        return

    # Derive a shared secret from ECC key exchange
    shared_secret = derive_shared_secret(sender_ec_private, receiver_ec_public)

    # Generate a random symmetric key for message encryption
    symmetric_key = generate_symmetric_key()

    # Encrypt the email message with the symmetric key
    start_time = time.time()  # Start measuring encryption time
    ciphertext = encrypt_message(message, symmetric_key)
    encryption_time = time.time() - start_time  # Calculate encryption time

    # Encrypt the symmetric key with the recipient's RSA public key
    symmetric_key_ciphertext = rsa_encrypt_symmetric_key(symmetric_key, receiver_rsa_public)

    # Generate a digital signature for the email
    start_time = time.time()
    signature = generate_signature(sender_ec_private, message)
    signature_generation_time = time.time() - start_time
    print(f"Signature Generation Time: {signature_generation_time:.6f} seconds")

    print("Email sent securely.")

    # Simulate email reception

    # Decrypt the symmetric key with the recipient's RSA private key
    symmetric_key_received = rsa_decrypt_symmetric_key(symmetric_key_ciphertext, receiver_rsa_private)

    # Verify the digital signature
    start_time = time.time()
    signature_valid = verify_signature(sender_ec_public, message, signature)
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
    print(f"ECC Key Exchange Time: {key_exchange_time_ec:.6f} seconds")
    print(f"RSA Key Exchange Time: {key_exchange_time_rsa:.6f} seconds")
    print(f"Signature Generation Time: {signature_generation_time:.6f} seconds")
    print(f"Signature Verification Time: {signature_verification_time:.6f} seconds")
    print(f"Encryption Time: {encryption_time:.6f} seconds")
    print(f"Decryption Time: {decryption_time:.6f} seconds")

if __name__ == "__main__":
    simulate_hybrid_secure_email()
