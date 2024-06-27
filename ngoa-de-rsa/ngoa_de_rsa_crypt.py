import random
import numpy as np
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
import os

def is_prime(n, k=5):
    if n <= 1 or n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def fitness(candidate):
    return 1 if is_prime(candidate) else 0

def initialize_population(n, d, l, u):
    return [random.getrandbits(d) | 1 for _ in range(n)]

def ngo_phase(X, f, P):
    for i in range(len(X)):
        if f[i] == 0:
            X[i] = random.getrandbits(len(bin(max(X))) - 2) | 1
    return X

def de_phase(X, f, D):
    for i in range(len(X)):
        if f[i] == 0:
            X[i] = random.getrandbits(len(bin(max(X))) - 2) | 1
    return X

def enforce_prime_constraints(X, l, u):
    return [max(l, min(u, x | 1)) for x in X]

def select_best(X, t, f, tf):
    return [t[i] if tf[i] > f[i] else X[i] for i in range(len(X))]

def ngo_de_rsa_prime_number_generation(n, d, l, u, k, M, P, D):
    X = initialize_population(n, d, l, u)
    best_solution = None

    for iteration in range(M):
        f = [fitness(x) for x in X]
        X = ngo_phase(X, f, P)
        X = enforce_prime_constraints(X, l, u)
        best_solution = X[np.argmax(f)]

        t = de_phase(X, f, D)
        t = enforce_prime_constraints(t, l, u)
        tf = [fitness(x) for x in t]

        X = select_best(X, t, f, tf)

        if any(is_prime(x) for x in X):
            best_solution = X[np.argmax(tf)]
            break

    return best_solution

# Define parameters
n = 50  # Number of goshawks (population size)
d = 1024  # Dimension of search space (key bit size)
l = 2 ** (d - 1)  # Lower bound for prime numbers
u = 2 ** d - 1  # Upper bound for prime numbers
k = 1024  # Desired RSA key length
M = 1000  # Maximum iterations
P = {}  # NGOA parameters
D = {}  # DE parameters (mutation factor, crossover rate)

# Generate RSA keys using NGOA-DE
print("Generating RSA keys using NGOA-DE...")
p = ngo_de_rsa_prime_number_generation(n, d, l, u, k, M, P, D)
q = ngo_de_rsa_prime_number_generation(n, d, l, u, k, M, P, D)

n_rsa = p * q
phi = (p - 1) * (q - 1)
e = 65537
d_rsa = inverse(e, phi)

print(f"Public key (n, e): ({n_rsa}, {e})")
print(f"Private key (n, d): ({n_rsa}, {d_rsa})")

def rsa_encrypt(data, n, e):
    data_int = bytes_to_long(data)
    encrypted_int = pow(data_int, e, n)
    return long_to_bytes(encrypted_int)

def rsa_decrypt(data, n, d):
    data_int = bytes_to_long(data)
    decrypted_int = pow(data_int, d, n)
    return long_to_bytes(decrypted_int)

def encrypt_file(input_file, output_file, n, e):
    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted_data = rsa_encrypt(data, n, e)

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(input_file, output_file, n, d):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = rsa_decrypt(encrypted_data, n, d)

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

# Get user input for file path
input_file = input("Enter the path of the file to encrypt: ")

# Determine the folder and filenames for the encrypted and decrypted files
folder = os.path.dirname(input_file)
filename = os.path.basename(input_file)
encrypted_file = os.path.join(folder, f"encrypted_{filename}")
decrypted_file = os.path.join(folder, f"decrypted_{filename}")

# Encrypt the file
print(f"Encrypting file {input_file}...")
encrypt_file(input_file, encrypted_file, n_rsa, e)
print(f"Encrypted file saved as {encrypted_file}")

# Decrypt the file
print(f"Decrypting file {encrypted_file}...")
decrypt_file(encrypted_file, decrypted_file, n_rsa, d_rsa)
print(f"Decrypted file saved as {decrypted_file}")

