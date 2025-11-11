# Custom Cipher: Combined Vigenère-Affine Cryptosystem

A Python implementation of a two-stage classical cipher combining Vigenère and Affine encryption techniques, along with cryptanalysis tools to break it.

## 👥 Team Members
- CT-22053
- CT-22059
- CT-22063
- CT-22095

## 🔐 Overview
This project implements a custom cipher that combines two classical encryption techniques:
1. **Stage 1**: Vigenère cipher (polyalphabetic substitution)
2. **Stage 2**: Affine cipher (mathematical transformation)

The system requires a minimum 10-character Vigenère key and ensures the Affine parameter `a` is coprime with 26.

## ✨ Features
- **Encryption/Decryption**: Full implementation of the two-stage cipher
- **Cryptanalysis Tools**:
  - Frequency-based attack using chi-squared analysis
  - Known-plaintext attack (KPA)
  - Index of Coincidence for key length estimation
- **Security Metrics**: Mutual Information and statistical analysis
- **Performance Benchmarking**: Time complexity analysis across different text lengths
- **Automated Experiments**: Success rate testing for various attack scenarios
- **Visualization**: Matplotlib plots and CSV exports of experimental results

## 📊 Attack Methods
1. **Frequency Analysis**: Breaks the cipher by analyzing letter frequencies and comparing against English language distribution
2. **Known-Plaintext Attack**: Recovers keys when partial plaintext is known
3. **Index of Coincidence**: Estimates Vigenère key length for targeted attacks

## 🚀 Usage

# Encrypt a message
cipher = encrypt_combined("YOUR MESSAGE", "SECURITYKEY", a=5, b=8)

# Decrypt with keys
plain = decrypt_combined(cipher, "SECURITYKEY", a=5, b=8)

# Attack without keys
success, details = attack_frequency_then_vigenere(cipher)


## 📈 Experimental Results
The code includes comprehensive experiments measuring:
- Attack success rates vs. ciphertext length
- Known-plaintext attack effectiveness vs. snippet length
- Encryption/decryption performance benchmarks
- Randomized stress testing with varying parameters

## 🛠️ Requirements
- Python 3.x
- matplotlib (optional, for visualizations)

## 📝 Course
Network and Information Security (CT-486)
