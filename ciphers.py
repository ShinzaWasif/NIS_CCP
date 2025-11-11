from collections import Counter, defaultdict
import math
from math import log2  
import random
import time
import string
import csv 

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not found. Plotting will be disabled.")
    print("Please install it: pip install matplotlib")


ALPHABET = string.ascii_uppercase
A2I = {c: i for i, c in enumerate(ALPHABET)}
I2A = {i: c for c, i in A2I.items()}

def clean_text(s: str) -> str:
    """Keep only A-Z and convert to uppercase."""
    return ''.join(ch for ch in s.upper() if ch in ALPHABET)

def modinv(a: int, m: int = 26) -> int | None:
    """Modular inverse of a mod m, or None if not invertible."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def vigenere_encrypt(plain: str, key: str) -> str:
    plain = clean_text(plain)
    key = clean_text(key)
    if len(key) < 1:
        raise ValueError('Vigenere key must be non-empty')
    out = []
    for i, ch in enumerate(plain):
        p = A2I[ch]
        k = A2I[key[i % len(key)]]
        out.append(I2A[(p + k) % 26])
    return ''.join(out)

def vigenere_decrypt(cipher: str, key: str) -> str:
    cipher = clean_text(cipher)
    key = clean_text(key)
    out = []
    for i, ch in enumerate(cipher):
        c = A2I[ch]
        k = A2I[key[i % len(key)]]
        out.append(I2A[(c - k) % 26])
    return ''.join(out)

def affine_encrypt(plain: str, a: int, b: int) -> str:
    plain = clean_text(plain)
    if math.gcd(a, 26) != 1:
        raise ValueError('a must be coprime with 26')
    out = []
    for ch in plain:
        p = A2I[ch]
        out.append(I2A[(a * p + b) % 26])
    return ''.join(out)

def affine_decrypt(cipher: str, a: int, b: int) -> str:
    cipher = clean_text(cipher)
    inv = modinv(a, 26)
    if inv is None:
        raise ValueError('a has no modular inverse mod 26')
    out = []
    for ch in cipher:
        c = A2I[ch]
        out.append(I2A[(inv * (c - b)) % 26])
    return ''.join(out)

def encrypt_combined(plain: str, vigenere_key: str, affine_a: int, affine_b: int) -> str:
    """Full encryption: first Vigenere, then Affine."""
    if len(clean_text(vigenere_key)) < 10:
        raise ValueError('Vigenere key must be at least 10 letters long (requirement)')
    stage1 = vigenere_encrypt(plain, vigenere_key)
    stage2 = affine_encrypt(stage1, affine_a, affine_b)
    return stage2


def decrypt_combined(cipher: str, vigenere_key: str, affine_a: int, affine_b: int) -> str:
    """Full decryption: first Affine-decrypt, then Vigenere-decrypt."""
    stage1 = affine_decrypt(cipher, affine_a, affine_b)
    stage2 = vigenere_decrypt(stage1, vigenere_key)
    return stage2

# Precomputed allowed 'a' values for Affine (coprime with 26)
ALLOWED_A = [a for a in range(1, 26) if math.gcd(a, 26) == 1]

ENGLISH_FREQ_ORDER = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'  # rough order
ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074
}

# A robust way to score how "English-like" a text is.
def chi_squared_score(text: str) -> float:
    """Calculates chi-squared score of text against English frequencies. Lower is better."""
    text = clean_text(text)
    n = len(text)
    if n == 0:
        return float('inf')
    
    counts = Counter(text)
    score = 0.0
    for ch in ALPHABET:
        observed = counts.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * n / 100.0
        score += (observed - expected) ** 2 / (expected + 1e-9)
    return score

def index_of_coincidence(text: str) -> float:
    """Calculates the Index of Coincidence for a given text."""
    n = len(text)
    if n <= 1:
        return 0.0
    freqs = Counter(text)
    total = sum(v * (v - 1) for v in freqs.values())
    return total / (n * (n - 1))

# Mutual Information Metric
def mutual_information(text1: str, text2: str) -> float:
    """Calculates the mutual information between two strings of equal length."""
    if len(text1) != len(text2):
        raise ValueError("Strings must be of equal length")
    
    pairs = Counter(zip(text1, text2))
    n = sum(pairs.values())
    if n == 0:
        return 0.0
        
    px = Counter(text1)
    py = Counter(text2)
    mi = 0.0
    
    for (x, y), count in pairs.items():
        pxy = count / n
        if pxy > 0: # Avoid log(0)
            mi += pxy * log2(pxy / ((px[x] / n) * (py[y] / n)))
    return mi

def guess_key_length_by_ic(text: str, max_k: int = 16) -> int:
    """Guess Vigenere key length using average IC of subtexts."""
    text = clean_text(text)
    best_k = 1
    best_score = 0.0
    # Start from 2, as k=1 is just Caesar and will have high IC anyway
    for k in range(2, max_k + 1):
        ics = []
        for i in range(k):
            period_sub = text[i::k]
            if len(period_sub) > 1:
                ics.append(index_of_coincidence(period_sub))
        
        if not ics:
            continue
            
        avg_ic = sum(ics) / len(ics)
        # English IC ~ 0.066, random text ~ 0.038
        if avg_ic > best_score:
            best_score = avg_ic
            best_k = k
    return best_k

def break_vigenere_by_freq(cipher: str, key_len: int) -> str:
    """Classical frequency-based per-column Caesar solving for Vigenere key.
    Returns guessed key (A..Z).
    """
    cipher = clean_text(cipher)
    key_chars = []
    for i in range(key_len):
        col = cipher[i::key_len]
        if len(col) == 0:
            key_chars.append('A') # Append placeholder if column is empty
            continue
            
        # For each possible shift (0..25), shift column back and compute chi-sq with English freq
        best_shift = 0
        best_score = float('inf')
        n = len(col)
        col_counts = Counter(col)
        
        for s in range(26):
            # shift back by s => assume key letter = s
            chi2_col = 0.0
            for ch in ALPHABET:
                observed = col_counts.get(I2A[(A2I[ch] + s) % 26], 0)
                expected = ENGLISH_FREQ[ch] * n / 100.0
                chi2_col += (observed - expected) ** 2 / (expected + 1e-9) # Add epsilon to avoid division by zero
                
            if chi2_col < best_score:
                best_score = chi2_col
                best_shift = s
                
        key_chars.append(I2A[best_shift])
    return ''.join(key_chars)

def attack_frequency_then_vigenere(cipher: str, max_key_len: int = 16) -> tuple[bool, dict]:
    """Brute-force affine parameters (a,b), invert affine, then try to break Vigenere.
    Returns tuple(success_flag, details) for the *best* guess (lowest chi-squared).
    """
    cipher = clean_text(cipher)
    
    best_guess_details = {}
    best_score = float('inf')

    # try all affine (a,b) combinations (12 * 26 = 312 total)
    for a in ALLOWED_A:
        for b in range(26):
            # invert affine
            try:
                stage = affine_decrypt(cipher, a, b)
            except Exception:
                continue 
                
            guessed_k = guess_key_length_by_ic(stage, max_k=min(max_key_len, 20))
            if guessed_k == 0: continue

            guessed_key = break_vigenere_by_freq(stage, guessed_k)
            if not guessed_key: continue
            
            plain_guess = vigenere_decrypt(stage, guessed_key)
            
            # Use the chi-squared score to find the best match
            score = chi_squared_score(plain_guess)
            
            if score < best_score:
                best_score = score
                best_guess_details = {
                    'affine_a': a,
                    'affine_b': b,
                    'vigenere_key_guess': guessed_key,
                    'key_len': guessed_k,
                    'plaintext_guess': plain_guess,
                    'chi2_score': score
                }

    # A normalized chi-squared score (score per character) < 20 is very likely English.
    # Random text is often > 300. This threshold filters out failed breaks.
    if best_guess_details and (best_score / (len(cipher) + 1e-9)) < 20:
        return True, best_guess_details
    else:
        return False, best_guess_details # Return best (but failed) guess

def known_plaintext_attack(cipher: str, plain_known: str, known_pos: int = 0, max_vig_len: int = 20) -> dict | None:
    """Given a snippet of known plaintext, try to recover affine (a,b) and Vigenere key.
    Uses chi-squared score to validate the final plaintext and avoid false positives.
    """
    C = clean_text(cipher)
    P = clean_text(plain_known)
    if known_pos < 0 or known_pos + len(P) > len(C) or len(P) == 0:
        return None
        
    C_segment = C[known_pos:known_pos + len(P)]
    
    for a in ALLOWED_A:
        for b in range(26):
            V_segment = affine_decrypt(C_segment, a, b)
            diffs = [(A2I[V_segment[i]] - A2I[P[i]]) % 26 for i in range(len(P))]
            
            for klen in range(1, max_vig_len + 1):
                consistent = True
                candidate = [None] * klen
                
                for idx, d in enumerate(diffs):
                    pos = (known_pos + idx) % klen
                    if candidate[pos] is None:
                        candidate[pos] = d
                    elif candidate[pos] != d:
                        consistent = False
                        break
                        
                if consistent:
                    # Key must be fully determined by the snippet
                    if any(v is None for v in candidate):
                        continue
                        
                    key = ''.join(I2A[v] for v in candidate)
                    
                    plaintext_full = decrypt_combined(C, key, a, b)
                    
                    # Use chi-squared score to validate
                    score = chi_squared_score(plaintext_full)
                    normalized_score = score / (len(plaintext_full) + 1e-9)

                    if normalized_score < 20: # Threshold for "English-like"
                        return {'affine_a': a, 'affine_b': b, 'vigenere_key': key, 'plaintext_full': plaintext_full, 'chi2_score': score}
    return None

def plot_experiment_results(results: dict, title: str, xlabel: str, ylabel: str = "Success Rate"):
    """Uses matplotlib to plot experiment results and save them to a file."""
    if not MATPLOTLIB_AVAILABLE:
        print(f"Skipping plot: {title} (matplotlib not installed)")
        return
        
    x = list(results.keys())
    # Check if we have multiple metrics
    if 'success_rate_plain' in list(results.values())[0]:
        y_plain = [results[k]['success_rate_plain'] for k in x]
        y_key = [results[k]['success_rate_key'] for k in x]
        plt.figure(figsize=(7, 5))
        plt.plot(x, y_plain, marker='o', label='Plaintext Match')
        plt.plot(x, y_key, marker='s', linestyle='--', label='Full Key Match')
        plt.legend()
    else:
        # Fallback for simple success rate
        y = [results[k]['success_rate'] for k in x]
        plt.figure(figsize=(6, 4))
        plt.plot(x, y, marker='o')

    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.ylim(-0.05, 1.05) # Show 0% to 100%
    plt.grid(True)
    
    filename = title.lower().replace(' ', '_').replace('/', '_') + '.png'
    try:
        plt.savefig(filename)
        print(f"Plot saved to {filename}")
    except Exception as e:
        print(f"Error saving plot {filename}: {e}")
    
    plt.show()

def save_results_to_csv(filename: str, results: dict, xlabel: str):
    """Saves experiment results to a CSV file."""
    try:
        with open(filename, 'w', newline='') as f:
            headers = [xlabel, 'success_rate_plain', 'success_rate_key', 'avg_time_s']
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for x, vals in results.items():
                writer.writerow([
                    x, 
                    vals.get('success_rate_plain', 'N/A'), 
                    vals.get('success_rate_key', 'N/A'), 
                    vals['avg_time_s']
                ])
        print(f"Results saved to {filename}")
    except IOError as e:
        print(f"Error saving results to {filename}: {e}")


def random_english_like(n: int) -> str:
    """Generates a string of n characters sampling from English letter frequencies."""
    letters = list(ENGLISH_FREQ.keys())
    weights = [ENGLISH_FREQ[ch] for ch in letters]
    s = ''.join(random.choices(letters, weights=weights, k=n))
    
    # try to inject some common words occasionally to help frequency analysis
    for _ in range(max(1, n // 50)):
        w = random.choice(['THE', 'AND', 'OF', 'TO', 'IN', 'FOR', 'IS', 'THAT'])
        pos = random.randrange(0, max(1, n - len(w) + 1))
        s = s[:pos] + w + s[pos + len(w):]
    return s

def experiment_frequency_attack_success(vig_key: str, a: int, b: int, lengths: list[int], trials_per_length: int = 10):
    """Runs experiment for frequency-based attack success vs. ciphertext length."""
    results = {}
    for L in lengths:
        succ_plain = 0 
        succ_key = 0    
        total_time = 0.0
        print(f"  Testing freq attack for length {L} ({trials_per_length} trials)...")
        
        for t in range(trials_per_length):
            plain = random_english_like(L)
            clean_p = clean_text(plain)
            cipher = encrypt_combined(plain, vig_key, a, b)
            
            start = time.time()
            # Give attacker a bit of leeway on key length guess
            ok, details = attack_frequency_then_vigenere(cipher, max_key_len=min(20, len(vig_key) + 5)) 
            elapsed = time.time() - start
            total_time += elapsed
            
            if ok:
                # Check for full key recovery
                key_match = (details.get('affine_a') == a and
                             details.get('affine_b') == b and
                             details.get('vigenere_key_guess') == vig_key)
                if key_match:
                    succ_key += 1
                
                # Check if recovered plaintext matches
                if clean_text(details.get('plaintext_guess', '')) == clean_p:
                    succ_plain += 1
                    
        # Store both success rates
        results[L] = {
            'success_rate_plain': succ_plain / trials_per_length, 
            'success_rate_key': succ_key / trials_per_length, 
            'avg_time_s': total_time / trials_per_length
        }
    return results

def experiment_kpa_success(vig_key: str, a: int, b: int, snippet_lengths: list[int], trials_per_length: int = 5, full_text_len: int = 500):
    """Runs experiment for KPA success vs. known-plaintext snippet length."""
    results = {}
    for L in snippet_lengths:
        succ_plain = 0 
        succ_key = 0    
        total_time = 0.0
        print(f"  Testing KPA for snippet length {L} ({trials_per_length} trials)...")
        
        for t in range(trials_per_length):
            plain = random_english_like(full_text_len)
            clean_p = clean_text(plain)
            cipher = encrypt_combined(plain, vig_key, a, b)
            known_plain_snippet = plain[0:L] # Use first L chars as known plaintext
            
            start = time.time()
            res = known_plaintext_attack(cipher, known_plain_snippet, known_pos=0, max_vig_len=20)
            elapsed = time.time() - start
            total_time += elapsed
            
            if res:
                # Check for full key recovery
                key_match = (res.get('affine_a') == a and
                             res.get('affine_b') == b and
                             res.get('vigenere_key') == vig_key)
                if key_match:
                    succ_key += 1

                # Check if recovered plaintext matches
                if clean_text(res.get('plaintext_full', '')) == clean_p:
                    succ_plain += 1
                    
        # Store both success rates
        results[L] = {
            'success_rate_plain': succ_plain / trials_per_length, 
            'success_rate_key': succ_key / trials_per_length, 
            'avg_time_s': total_time / trials_per_length
        }
    return results

# Randomized Attack Stress Testing
def experiment_randomized_conditions(trials: int = 10, text_len: int = 400, max_k: int = 16):
    """Tests frequency attack robustness against random keys and parameters."""
    print(f"\nRunning randomized stress test ({trials} trials, text_len={text_len})...")
    results_plain = []
    results_key = []
    
    for t in range(trials):
        # Generate random keys
        a = random.choice(ALLOWED_A)
        b = random.randint(0, 25)
        klen = random.randint(10, 15) # Meet key req of >= 10
        key = ''.join(random.choices(ALPHABET, k=klen))
        
        plain = random_english_like(text_len)
        clean_p = clean_text(plain)
        cipher = encrypt_combined(plain, key, a, b)
        
        ok, details = attack_frequency_then_vigenere(cipher, max_key_len=max_k)
        
        if ok:
            key_match = (details.get('affine_a') == a and
                         details.get('affine_b') == b and
                         details.get('vigenere_key_guess') == key)
            plain_match = (details.get('plaintext_guess') == clean_p)
            
            results_key.append(key_match)
            results_plain.append(plain_match)
        else:
            results_key.append(False)
            results_plain.append(False)
            
    succ_rate_plain = sum(results_plain) / len(results_plain) if results_plain else 0
    succ_rate_key = sum(results_key) / len(results_key) if results_key else 0
    
    print(f"Randomized condition success: Plaintext Match={succ_rate_plain:.2f}, Key Match={succ_rate_key:.2f}")
    return {'plain_success': succ_rate_plain, 'key_success': succ_rate_key}

# Performance Profiling
def benchmark_encryption(vig_key: str, a: int, b: int, lengths=[100, 500, 1000, 2000, 5000, 10000]):
    """Benchmarks encryption and decryption speed vs. text length."""
    print(f"\n--- Performance Benchmark (Key: {vig_key}, a={a}, b={b}) ---")
    for L in lengths:
        text = random_english_like(L)
        
        start_enc = time.time()
        cipher = encrypt_combined(text, vig_key, a, b)
        enc_time = time.time() - start_enc
        
        start_dec = time.time()
        _ = decrypt_combined(cipher, vig_key, a, b)
        dec_time = time.time() - start_dec
        
        print(f"  Length={L: <6}: Encrypt={enc_time:.6f}s, Decrypt={dec_time:.6f}s")

if __name__ == '__main__':
    print('--- Basic Encryption/Decryption Demo ---')
    vig_key = 'SECURITYISFUN'  # 13 chars (meets >= 10)
    a = 5
    b = 8

    sample_plain = 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG'
    clean_plain = clean_text(sample_plain)
    
    cipher = encrypt_combined(sample_plain, vig_key, a, b)
    recovered = decrypt_combined(cipher, vig_key, a, b)

    print(f'Sample plaintext: {clean_plain}')
    print(f'Vigenere key:     {vig_key}')
    print(f'Affine params:    a={a}, b={b}')
    print(f'Ciphertext:       {cipher}')
    print(f'Recovered:        {recovered}')
    print(f'Match:            {recovered == clean_plain}')

    print('\n--- Known-Plaintext Attack (KPA) Demo ---')
    known_plain_snippet = 'THEQUICKBROWNFOXJUMPS' 
    print(f'Running KPA with known snippet: "{known_plain_snippet}"')
    res_kpa = known_plaintext_attack(cipher, known_plain_snippet, known_pos=0, max_vig_len=15)
    if res_kpa:
        print('KPA SUCCESS!')
        print(f"  Recovered a={res_kpa['affine_a']}, b={res_kpa['affine_b']}")
        print(f"  Recovered Vigenere key: {res_kpa['vigenere_key']}")
        print(f"  Recovered Plaintext: {res_kpa['plaintext_full']}")
        print(f"  Full plaintext match: {res_kpa['plaintext_full'] == clean_plain}")
    else:
        print('KPA FAILED. (This is unexpected for this demo)')

    print('\n--- Frequency-Based Attack Demo ---')
    freq_plain = random_english_like(500) # Use 500 chars
    freq_plain_clean = clean_text(freq_plain)
    freq_cipher = encrypt_combined(freq_plain, vig_key, a, b)
    
    print(f'Running frequency attack on {len(freq_plain_clean)}-char cipher...')
    ok, info = attack_frequency_then_vigenere(freq_cipher, max_key_len=15)
    
    print(f'Attack success: {ok}')
    if ok:
        print(f"  Guessed a={info['affine_a']}, b={info['affine_b']} (Real: a={a}, b={b})")
        print(f"  Guessed Vigenere key: {info['vigenere_key_guess']} (Real: {vig_key})")
        print(f"  Actual Plaintext: {freq_plain_clean}")
        print(f"  Plaintext guess:  {info['plaintext_guess']}")
        print(f"  Full plaintext match: {info['plaintext_guess'] == freq_plain_clean}")
    else:
        print("Attack failed to find a high-confidence match.")

    print('\n--- Experiment: Frequency Attack Success vs. Ciphertext Length ---')
    res_freq = experiment_frequency_attack_success(
        vig_key, a, b, 
        lengths=[200, 300, 500, 800, 1000], 
        trials_per_length=5
    )
    print('Frequency Attack Experiment results:')
    for L, stats in res_freq.items():
        print(f"  Length {L: <4}: plain_success={stats['success_rate_plain']:.2f}, key_success={stats['success_rate_key']:.2f}, avg_time_s={stats['avg_time_s']:.2f}")
    
    save_results_to_csv('freq_attack_results.csv', res_freq, 'CiphertextLength')

    print('\n--- Experiment: KPA Success vs. Known Snippet Length ---')
    res_kpa_exp = experiment_kpa_success(
        vig_key, a, b, 
        snippet_lengths=[15, 20, 25, 30, 35], 
        trials_per_length=5, 
        full_text_len=300
    )
    print('KPA Experiment results:')
    for L, stats in res_kpa_exp.items():
        print(f"  Snippet {L: <3}: plain_success={stats['success_rate_plain']:.2f}, key_success={stats['success_rate_key']:.2f}, avg_time_s={stats['avg_time_s']:.2f}")

    save_results_to_csv('kpa_attack_results.csv', res_kpa_exp, 'SnippetLength')

    plot_experiment_results(res_freq, "Frequency Attack Success vs Ciphertext Length", "Ciphertext Length")
    plot_experiment_results(res_kpa_exp, "KPA Success vs Known Snippet Length", "Known Snippet Length")

    experiment_randomized_conditions(trials=20, text_len=500, max_k=16)

    print('\n--- 7. Statistical Metrics Demo (Mutual Information) ---')
    mi_plain = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    mi_vigenere = vigenere_encrypt(mi_plain, vig_key)
    mi_full_cipher = affine_encrypt(mi_vigenere, a, b)
    print(f"  MI(plain, plain[1:]+'A'): {mutual_information(mi_plain, mi_plain[1:]+'A'):.4f} (High correlation)")
    print(f"  MI(plain, vigenere):      {mutual_information(mi_plain, mi_vigenere):.4f} (Should be lower)")
    print(f"  MI(plain, full_cipher):   {mutual_information(mi_plain, mi_full_cipher):.4f} (Should be lowest)")

    benchmark_encryption(vig_key, a, b)