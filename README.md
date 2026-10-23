# SecureCloud-X: Enhanced Multi-Cloud Storage Security Framework Using ML-KEM, Blockchain-Based Integrity Verification, and AI-Driven Threat Detection

A complete academic cybersecurity engineering project developed for B.Tech Final Year project evaluation and demonstration.

---

## 1. Project Title
**"Enhanced Multi-Cloud Storage Security Framework Using ML-KEM, Blockchain-Based Integrity Verification, and AI-Driven Threat Detection"**  
*Short Project Name:* **SecureCloud-X**

---

## 2. Abstract
Cloud storage architectures remain vulnerable to data breaches, single-cloud provider lock-in, unauthorized bit-level tampering, and credential abuse. Furthermore, emerging quantum computing capabilities threaten classical asymmetric algorithms (such as RSA and ECDH). SecureCloud-X enhances the multi-cloud storage paradigm established in the research paper *"CloudLock: Secure Data Sharing Using a Hybrid Cryptosystem in Multi-Cloud Data Storage"* through four targeted extensions:
1. Replacing pre-quantum ECDH with NIST FIPS 203 post-quantum **ML-KEM** (Kyber-768).
2. Implementing an immutable **Blockchain-style integrity ledger** using **SHA3-256** to detect unauthorized cloud-side tampering.
3. Incorporating an unsupervised **Isolation Forest** machine learning model for behavioral user anomaly detection.
4. Designing an application-level **Adaptive Secure Session Key Generator (ASKG)** built on NIST SP 800-90A HMAC-DRBG using SHA-256 with periodic reseeding and key rotation.

---

## 3. Problem Statement
Standard multi-cloud security systems suffer from four principal vulnerabilities:
1. **Quantum Vulnerability:** Key exchange relies heavily on classical discrete logarithm or integer factorization problems (ECDH/RSA), susceptible to Shor's algorithm on cryptanalytically relevant quantum computers.
2. **Silent Storage Tampering:** Cloud storage providers or malicious insiders can alter stored ciphertext without rapid detection by client applications.
3. **Static Access Policies:** Systems grant unrestricted file operations to authenticated users without evaluating anomalous session behaviors (e.g., mass download exfiltration or odd-hour access).
4. **Key Management Pitfalls:** Session keys are often generated via low-entropy pseudo-random functions or held in insecure database tables.

---

## 4. Objectives
- Design and implement a modular hybrid cryptosystem using **ChaCha20-Poly1305** for payload encryption.
- Encapsulate symmetric keys using **ML-KEM-768** with **HKDF-SHA256** key wrapping.
- Distribute encrypted payloads across three simulated independent cloud providers (**Cloud A, Cloud B, Cloud C**).
- Maintain an append-only **blockchain-style ledger** using SHA3-256 to guarantee verifiable proof-of-integrity.
- Detect abnormal user behavior in real time using **Isolation Forest** to block unauthorized exfiltration.
- Enforce strict key separation where raw cryptographic keys are never stored in the database or logs.

---

## 5. Existing System
The baseline research paper *"CloudLock"* utilized:
- ChaCha20-Poly1305 for symmetric encryption.
- Classical Elliptic Curve Diffie-Hellman (ECDH) for key agreement.
- Centralized key dissemination systems.
- Conventional hash-based checks without blockchain immutability.
- Static authentication without machine learning behavioral monitoring.

---

## 6. Proposed System
SecureCloud-X modernizes and reinforces the baseline architecture:
- **Post-Quantum Cryptography:** Classical ECDH is replaced with lattice-based ML-KEM-768 (FIPS 203).
- **Immutable Integrity Ledger:** A local blockchain ledger chains file SHA3-256 digests from a Genesis Block, enabling tamper detection before decryption is attempted.
- **AI-Driven Threat Mitigation:** Evaluates 9 behavioral features against an Isolation Forest model to compute normalized risk scores and block high-risk downloads.
- **Adaptive Key Generation (ASKG):** An application-level session key generator built on standard HMAC-DRBG with OS entropy seeding and lifecycle rotation.

---

## 7. Main Contributions
1. **Post-Quantum Key Encapsulation:** Implementation of ML-KEM-768 with clean modular abstraction and runtime status reporting (`ML-KEM MODE: ACTIVE`).
2. **Blockchain-Style SHA3 Integrity Ledger:** Cryptographic block sequence that detects single-bit alterations across distributed fragments.
3. **AI Threat Detection:** scikit-learn Isolation Forest model evaluating behavioral features in real-time.
4. **Adaptive Secure Key Generator (ASKG):** Application-level HMAC-DRBG with cryptographically secure OS entropy, additional entropy mixing, periodic reseeding, and rotation.

---

## 8. System Architecture

```
User (Browser Client)
       ↓
1. User Authentication (PBKDF2-HMAC-SHA256)
       ↓
2. ML Behavioral Feature Extraction
       ↓
3. Isolation Forest Threat Evaluation
       ├─ [High Risk > 0.70] → Access Blocked & Logged
       └─ [Normal / Low Risk] → Proceed
       ↓
4. ASKG Session Key Generation (HMAC-DRBG SHA-256)
       ↓
5. ChaCha20-Poly1305 File Encryption (256-bit Key + 12-byte Nonce)
       ↓
6. Post-Quantum ML-KEM-768 Encapsulation & HKDF-SHA256 Key Wrapping
       ↓
7. SHA3-256 Cryptographic Digest Calculation
       ↓
8. Blockchain-Style Ledger Block Creation (Linked to previous block hash)
       ↓
9. Payload Fragmentation (3 Chunks)
       ↓
10. Multi-Cloud Storage Distribution
       ├── Cloud A (storage_simulation/cloud_A/)
       ├── Cloud B (storage_simulation/cloud_B/)
       └── Cloud C (storage_simulation/cloud_C/)
```

---

## 9. Technology Stack

| Layer | Technology / Library | Role in Project |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.11+ / Flask 3.1+ | REST APIs, route controllers, session tracking |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript | Dark cybersecurity UI, interactive labs, async fetch |
| **Relational Database** | SQLite (`sqlite3`) | Metadata, key audit registry, blockchain, logs |
| **Symmetric Encryption** | `cryptography` (ChaCha20Poly1305) | Authenticated Encryption with Associated Data (AEAD) |
| **Post-Quantum KEM** | `kyber-py` (FIPS 203 ML-KEM) | Lattice-based post-quantum key encapsulation |
| **Key Derivation** | `cryptography` (HKDF-SHA256) | Derives wrapping keys from ML-KEM shared secrets |
| **Hashing & MAC** | `hashlib` (SHA-256, SHA3-256), `hmac` | Block headers, file integrity, HMAC-DRBG |
| **Machine Learning** | `scikit-learn` (Isolation Forest) | Behavioral anomaly detection and risk scoring |
| **Testing** | Python standard `unittest` | Automated end-to-end verification suite |

---

## 10. Module Description

1. **`auth_routes.py`:** User login, session management, PBKDF2 password hashing, and login failure tracking.
2. **`hmac_drbg.py`:** NIST SP 800-90A HMAC-DRBG implementation maintaining internal state $(K, V)$.
3. **`askg.py`:** Adaptive Secure Session Key Generator managing DRBG lifecycle, reseeding, rotation, and metadata.
4. **`chacha_service.py`:** ChaCha20-Poly1305 encryption and decryption with 12-byte random nonces.
5. **`mlkem_service.py`:** Post-quantum ML-KEM abstraction supporting ML-KEM-768 with clean development fallback.
6. **`key_manager.py`:** Hybrid KEM-DEM layer deriving wrapping keys via HKDF-SHA256 and wrapping session keys.
7. **`hash_service.py`:** SHA3-256 digest computation and constant-time integrity verification.
8. **`fragmentation.py`:** Splits ciphertext into $N$ fragments and reassembles ordered byte streams.
9. **`cloud_manager.py`:** Manages simulated Cloud A, B, and C storage, retrieval, and bit-corruption simulation.
10. **`block.py` & `ledger.py`:** Lightweight blockchain ledger recording immutable file transactions.
11. **`anomaly_detector.py`:** Runtime Isolation Forest inference calculating continuous risk scores ($[0.00, 1.00]$).
12. **`train_model.py`:** Standalone training script fitting Isolation Forest on the synthetic security events dataset.

---

## 11. Installation & Environment Setup

### Prerequisites
- Windows 10/11 (or Linux/macOS)
- Python 3.11 or 3.12
- VS Code (recommended)

### Installation Commands
```powershell
# 1. Navigate to the project directory
cd "C:\Users\Arnav Singh Sidhu\.gemini\antigravity\scratch\SecureCloud-X"

# 2. (Optional) Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\activate

# 3. Install required dependencies
pip install -r requirements.txt
```

---

## 12. How to Run the Project

```powershell
# Step 1: Initialize Database & Seed Demo Accounts
python init_db.py

# Step 2: Train the Machine Learning Model
python ml/train_model.py

# Step 3: Run the Automated Unit Test Suite
python -m unittest discover -s tests -p "test_*.py" -v

# Step 4: Start the Flask Application
python app.py
```

Open your browser and visit: **`http://127.0.0.1:5000`**

### Default Demo Credentials
- **Username:** `admin` | **Password:** `admin123` (Role: Admin)
- **Username:** `student` | **Password:** `student123` (Role: User)
*(Notice: Credentials are provided for local academic demonstration only).*

---

## 13. How to Train the ML Model
The project includes a synthetic dataset representing realistic normal activities and anomalous exfiltration patterns in `ml/security_events.csv`.
To retrain the Isolation Forest model:
```powershell
python ml/train_model.py
```
This fits the model using 15% contamination and persists the scaler and estimator to `ml/model.pkl`.  
*Notice: The ML dataset is synthetic and created for prototype evaluation.*

---

## 14. How File Upload Works
1. User logs in and selects a file on `/upload`.
2. The user's active session features are passed to `anomaly_detector.py`.
3. If risk score $\le 0.70$, the ASKG module generates a fresh 256-bit session key via HMAC-DRBG.
4. ChaCha20-Poly1305 encrypts the file payload with a random 12-byte nonce.
5. ML-KEM-768 encapsulates against the system's public key, generating a shared secret.
6. HKDF-SHA256 expands the shared secret into a 256-bit wrapping key, which encrypts the session key.
7. SHA3-256 computes the cryptographic digest of the complete ciphertext.
8. A new block is mined and committed to the blockchain ledger.
9. The ciphertext is split into 3 fragments and stored across `storage_simulation/cloud_A/`, `cloud_B/`, and `cloud_C/`.
10. The browser displays the 8-stage breakdown with execution latencies.

---

## 15. How File Download Works
1. User requests a file download on `/files` or `/download/<file_id>`.
2. Anomaly detector evaluates download frequency and volume.
3. System fetches fragments from Cloud A, Cloud B, and Cloud C and reassembles the ciphertext.
4. System recalculates the SHA3-256 digest and compares it with the blockchain record.
5. If verified, the system decapsulates ML-KEM ciphertext, derives the wrapping key via HKDF, recovers the session key, decrypts with ChaCha20-Poly1305, and streams the original file to the browser.
6. If a mismatch is detected, decryption is halted immediately.

---

## 16. How Tampering Detection Works
1. Navigate to **"My Files"** (`/files`).
2. Click the red **"Simulate Tamper"** button next to any uploaded file.
3. The server intentionally flips bits in Cloud Provider A's fragment file.
4. The file is retrieved and reconstructed, and its SHA3-256 digest is computed.
5. Because the reconstructed bytes differ from the original, the hash mismatch is caught against the blockchain record:
   ```
   --------------------------------
   INTEGRITY VERIFICATION
   --------------------------------
   Expected Hash (Blockchain): c8a1b2...
   Calculated Hash (Cloud):    7f3e1a...

   STATUS: TAMPERING DETECTED — DECRYPTION BLOCKED
   ```
6. Attempting to download the file directly produces a prominent warning and prevents decryption.

---

## 17. How ML Threat Detection Works
1. Navigate to **"ML Threat Detection"** (`/security`).
2. Click **"Generate Normal Activity"**:
   - Features: failed logins = 0, downloads = 1, volume = 4.5 MB, hour = 14.
   - Result: `Prediction: NORMAL`, `Risk: ~0.15`, `Decision: ALLOW`.
3. Click **"Generate Suspicious Activity"**:
   - Features: failed logins = 8, downloads = 45, volume = 2.8 GB, hour = 3 AM, new IP = 1.
   - Result: `Prediction: ANOMALY`, `Risk: ~0.85`, `Decision: BLOCK`.
   - Action: *"Operation blocked by AI threat detection engine. Excessive risk."*

---

## 18. How Key Generation Works (ASKG & HMAC-DRBG)
1. Navigate to **"Key Lab (ASKG)"** (`/keygen-lab`).
2. Review the generator parameters:
   - Algorithm: NIST SP 800-90A HMAC-DRBG
   - Hash: SHA-256
   - Key Size: 256 bits (32 bytes)
3. Test key operations:
   - **"+ Generate Key"**: Generates a new session key and logs metadata.
   - **"Reseed DRBG"**: Injects fresh operating system entropy (`os.urandom(32)`).
   - **"Rotate Active Key"**: Marks previous key as `Rotated` and establishes a fresh key.
4. Safe Key Guarantee: Raw cryptographic keys are kept only in volatile RAM and **NEVER** stored in SQLite or displayed in the UI.

---

## 19. Performance Evaluation & Cryptographic Benchmarks
Navigate to **"Performance"** (`/performance`) and click **"Run Live Benchmark Suite"**.  
The suite runs live tests across 10 KB, 100 KB, 1 MB, 5 MB, and 10 MB payloads using high-precision CPU timers (`time.perf_counter`):
- Key generation latency (ms)
- ChaCha20-Poly1305 encryption & decryption latency (ms)
- ML-KEM-768 encapsulation & decapsulation latency (ms)
- SHA3-256 hashing latency (ms)
- Blockchain verification latency (ms)
- Machine learning inference latency (ms)
- Throughput (MB/s)
- Comparison of OS CSPRNG, standard HMAC-DRBG, and ASKG.  
*(Notice: All values are measured live on your machine without fabricated figures).*

---

## 20. Limitations
1. **Simulated Multi-Cloud Storage:** Multi-cloud repositories are simulated using local workstation folders (`storage_simulation/`) to ensure full academic reproducibility without requiring external cloud accounts or billing credentials.
2. **Synthetic ML Training Dataset:** The Isolation Forest model is trained on a synthetic dataset representative of prototype threat profiles. Real-world deployments would calibrate on continuous organization-specific SIEM audit feeds.
3. **Local Blockchain:** The blockchain-style ledger is a localized cryptographic integrity ledger rather than a distributed Proof-of-Work / Proof-of-Stake consensus network.

---

## 21. Future Scope
- Integrating live cloud storage connectors (AWS S3 SDK, Azure Blob SDK, Google Cloud Storage SDK).
- Implementing $(k, n)$ Shamir's Secret Sharing or Reed-Solomon Erasure Coding across cloud fragments for fault-tolerant reconstruction during cloud outages.
- Deploying decentralized distributed ledgers (e.g., Hyperledger Fabric or private Ethereum networks) for multi-tenant consensus.
- Incorporating deep learning autoencoders for temporal user behavior sequence modeling.

---

