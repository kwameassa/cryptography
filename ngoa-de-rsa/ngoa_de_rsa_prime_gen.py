import random
import numpy as np


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


def fitness(candidate):
    # Higher fitness for being closer to prime
    return 1 if is_prime(candidate) else 0


def initialize_population(n, d, l, u):
    return [random.getrandbits(d) | 1 for _ in range(n)]  # Ensure they are odd


def ngo_phase(X, f, P):
    # Placeholder for the NGOA phase updates
    for i in range(len(X)):
        if f[i] == 0:  # If not prime
            X[i] = random.getrandbits(len(bin(max(X))) - 2) | 1  # Generate new odd candidate
    return X


def de_phase(X, f, D):
    # Placeholder for the DE phase updates
    for i in range(len(X)):
        if f[i] == 0:  # If not prime
            X[i] = random.getrandbits(len(bin(max(X))) - 2) | 1  # Generate new odd candidate
    return X


def enforce_prime_constraints(X, l, u):
    # Ensure the numbers are within bounds and odd
    return [max(l, min(u, x | 1)) for x in X]


def select_best(X, t, f, tf):
    # Select the best solutions from both NGOA and DE phases
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

# Generate two prime numbers
p = ngo_de_rsa_prime_number_generation(n, d, l, u, k, M, P, D)
q = ngo_de_rsa_prime_number_generation(n, d, l, u, k, M, P, D)

print(f"Generating prime number p: {p}")
print(f"Generating prime number q: {q}")

# Perform Miller-Rabin Primality Test on p and q
print(f"\nMiller-Rabin Primality Test Results:")
print(f"p is prime: {is_prime(p)}")
print(f"q is prime: {is_prime(q)}")
