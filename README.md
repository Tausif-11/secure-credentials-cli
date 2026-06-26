# Zero-Knowledge Cryptographic Password Vault

An advanced command-line password manager written in Python emphasizing zero-knowledge data isolation mechanisms, memory-hard authentication, and verified ciphertext standards.

## 🛡️ Cryptographic Specification

- **Key Derivation Function (KDF):** Argon2id (Profiles: 64MB RAM, 3 Passes, 4 Parallel execution tracks) to structurally compromise high-velocity brute force GPU clustering designs.
- **Symmetric Encryption Engine:** Advanced Encryption Standard operating within Galois/Counter Mode (AES-256-GCM). Provides authenticated metadata ensuring runtime operational assertions against active local block file tampering attempts.
- **Authentication Safety:** Constant-time hash verification via `hmac.compare_digest` prevents leakage through physical hardware CPU timing profiles.

## 🚀 Getting Started

### 1. Requirements Allocation
Make sure you have Python 3.10+ installed. Install the security architecture dependencies:
```bash
pip install -r requirements.txt

2. Run the Local Application
Bash
python main.py

3. Usage Rules
Initialization: Upon first initialization run, the system prompts you to create a Master Password. This password dictates core entropy settings and cannot be reset if lost.

Operation: Your database creates an encrypted data file named vault.db. Plaintext content strings are never loaded to permanent sectors. All encryption transformations process strictly inside local temporary program heap threads.