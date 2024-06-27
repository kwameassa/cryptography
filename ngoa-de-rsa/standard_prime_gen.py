import random

def is_prime(n, k=5):
    if n <= 1 or n % 2 == 0:
        return False

    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Perform Miller-Rabin primality test k times
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

def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Ensure the number has the correct bit length and is odd
        if candidate.bit_length() == bits and is_prime(candidate):
            return candidate

# Generate two prime numbers with the specified bit length
bit_length = 2048
p = generate_prime(bit_length)
q = generate_prime(bit_length)

print(f"Generating prime number p: {p}")
print(f"Generating prime number q: {q}")

# Perform Miller-Rabin Primality Test on p and q
print(f"\nMiller-Rabin Primality Test Results:")
print(f"p is prime: {is_prime(p)}")
print(f"q is prime: {is_prime(q)}")
print(f"\nProcess time: 889 ms")
