import timeit
from phe import paillier
from Crypto.PublicKey import ElGamal
from Crypto.Util import number
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt # Requires: pip install matplotlib

print("\n--- Add'l Q1d: Performance Analysis (Benchmarking) ---")

# --- Setup Keys ---
print("Generating keys for all schemes...")
# Paillier
pk_paillier, sk_paillier = paillier.generate_paillier_keypair(n_length=1024)

# ElGamal
key_elgamal = ElGamal.generate(1024, get_random_bytes)
pk_elgamal = key_elgamal.publickey()
sk_elgamal = key_elgamal

# --- Setup Data ---
m1_int, m2_int = 12345, 67890
c1_paillier = pk_paillier.encrypt(m1_int)
c2_paillier = pk_paillier.encrypt(m2_int)

# (Re-using helper functions from Q1a)
def elgamal_encrypt_bench(pub_key, m):
    p, g, y = pub_key.p, pub_key.g, pub_key.y
    k = number.getRandomRange(1, p - 1)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt_bench(priv_key, c1, c2):
    p, x = priv_key.p, priv_key.x
    s = pow(c1, x, p)
    s_inv = number.inverse(s, p)
    m = (c2 * s_inv) % p
    return m

c1_elgamal = elgamal_encrypt_bench(pk_elgamal, m1_int)
c2_elgamal = elgamal_encrypt_bench(pk_elgamal, m2_int)
c_sum_paillier = c1_paillier + c2_paillier
c_prod_elgamal = (
    (c1_elgamal[0] * c2_elgamal[0]) % pk_elgamal.p,
    (c1_elgamal[1] * c2_elgamal[1]) % pk_elgamal.p
)

# --- Timeit Execution ---
n_iterations = 500
print(f"Running benchmarks ({n_iterations} iterations each)...")
results = {}

# Paillier
results['Paillier Enc'] = timeit.timeit(
    lambda: pk_paillier.encrypt(m1_int), number=n_iterations)
results['Paillier Dec'] = timeit.timeit(
    lambda: sk_paillier.decrypt(c1_paillier), number=n_iterations)
results['Paillier Add (Homomorphic)'] = timeit.timeit(
    lambda: c1_paillier + c2_paillier, number=n_iterations)

# ElGamal
results['ElGamal Enc'] = timeit.timeit(
    lambda: elgamal_encrypt_bench(pk_elgamal, m1_int), number=n_iterations)
results['ElGamal Dec'] = timeit.timeit(
    lambda: elgamal_decrypt_bench(sk_elgamal, c1_elgamal[0], c1_elgamal[1]), number=n_iterations)
results['ElGamal Mul (Homomorphic)'] = timeit.timeit(
    lambda: (c1_elgamal[0] * c2_elgamal[0]) % pk_elgamal.p, number=n_iterations)

print("\n--- Benchmark Results ---")
print(f"Total time for {n_iterations} iterations (lower is better):")
for op, time_taken in results.items():
    print(f"  {op:<25}: {time_taken:.6f} seconds")

# --- Plotting ---
try:
    names = list(results.keys())
    values = list(results.values())
    
    plt.figure(figsize=(12, 6))
    bars = plt.barh(names, values)
    plt.xlabel(f'Total Time for {n_iterations} Operations (seconds)')
    plt.title('PHE Performance Comparison (1024-bit keys)')
    plt.gca().invert_yaxis() # Paillier first
    
    # Add text labels
    for bar in bars:
        plt.text(bar.get_width(), bar.get_y() + bar.get_height()/2,
                 f' {bar.get_width():.4f}s',
                 va='center', ha='left')

    plt.tight_layout()
    print("\nPlotting results... (Close the plot window to exit)")
    plt.show()

except ImportError:
    print("\n'matplotlib' not found. Skipping plot.")
    print("Install it with 'pip install matplotlib' to see the graph.")
