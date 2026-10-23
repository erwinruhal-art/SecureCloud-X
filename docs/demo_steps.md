# SecureCloud-X: Viva Presentation & Demonstration Walkthrough

This document outlines the exact, step-by-step demonstration sequence to follow when presenting SecureCloud-X in front of project evaluators and professors.

---

## 1. Quick Launch Checklist

Open PowerShell or Command Prompt in the project folder:
```powershell
cd "C:\Users\Arnav Singh Sidhu\.gemini\antigravity\scratch\SecureCloud-X"

# Step A: Initialize the database (if not already done)
python init_db.py

# Step B: Train the ML model
python ml/train_model.py

# Step C: Run the automated unit tests
python -m unittest discover -s tests -p "test_*.py" -v

# Step D: Start the web application
python app.py
```
Open your browser and navigate to: `http://127.0.0.1:5000`

---

## 2. Step-by-Step Viva Demonstration Sequence

### Step 1: Authentication & RBAC (Module 1)
- **Action:** At `http://127.0.0.1:5000/login`, log in with:
  - **Username:** `admin`
  - **Password:** `admin123`
- **What to Explain:**
  - Passwords are salted and hashed using **PBKDF2-HMAC-SHA256**.
  - Login attempts (successful or failed), IP addresses, and user-agents are recorded in the security log and feed the anomaly detection feature vector.

---

### Step 2: System Dashboard & Status Banners (Module 11 & 23)
- **Action:** Observe the top navigation bar and dashboard cards.
- **What to Point Out:**
  - Notice the green badge: **ML-KEM MODE: ACTIVE (ML-KEM-768)** confirming that post-quantum lattice cryptography (FIPS 203) is operational.
  - Notice the **Multi-Cloud Provider Status** cards showing Cloud A, Cloud B, and Cloud C are Online and ready.
  - Highlight the aggregate metrics: Total Users, Encrypted Files, Active Keys, Integrity Status.

---

### Step 3: Key Generation Lab (Module 2 & 17)
- **Action:** Click on **"Key Lab (ASKG)"** in the top navigation.
- **What to Demonstrate:**
  1. Click **"+ Generate Key"**: Observe the new key ID (`KEY-000X`) appended to the table.
  2. Click **"Reseed DRBG"**: Show that fresh operating system entropy (`os.urandom`) has been injected, incrementing the Reseed Count.
  3. Click **"Rotate Active Key"**: Show that the previous key status transitions to `Rotated` and a new active session key is established.
- **Key Viva Point to State:**
  - *"We did not invent an unverified cryptographic algorithm. Our ASKG is an application-level key management wrapper built strictly on NIST SP 800-90A HMAC-DRBG with SHA-256. It manages state $(K, V)$, collects high-entropy OS seeds, enforces periodic reseeding, and ensures raw secret keys are NEVER exposed in the UI or stored in SQLite."*

---

### Step 4: Cryptographic File Upload Pipeline (Module 13 & 4)
- **Action:** Navigate to **"Upload File"**, select any sample document or image (e.g., a PDF or text file), and click **"Encrypt & Distribute to Multi-Cloud"**.
- **What to Demonstrate:**
  - Point to the **8-Stage Pipeline Breakdown** with live timing metrics:
    - **Stage 1 (AI Threat Check):** Evaluated behavioral risk before processing.
    - **Stage 2 (ASKG Keygen):** Generated a 256-bit symmetric session key.
    - **Stage 3 (ChaCha20 AEAD):** Encrypted the file payload with a unique 12-byte nonce.
    - **Stage 4 (ML-KEM + HKDF):** Encapsulated the shared secret using post-quantum ML-KEM-768 and wrapped the session key via HKDF-SHA256.
    - **Stage 5 (SHA3-256 Hash):** Generated a cryptographic hash over the ciphertext.
    - **Stage 6 (Blockchain Ledger):** Mined Block #X linking previous block hash to the new file hash.
    - **Stage 7 & 8 (Fragmentation & Multi-Cloud):** Split the ciphertext into 3 fragments and distributed them into `storage_simulation/cloud_A/`, `cloud_B/`, and `cloud_C/`.
  - Open File Explorer to `storage_simulation/` to visually show the physical fragments stored across the three cloud directories.

---

### Step 5: File Download & Decryption Verification (Module 14)
- **Action:** Click **"Test Download & Integrity Verification"** (or click **"Download"** on the My Files page).
- **What to Explain:**
  - Reconstructs fragments from Cloud A, Cloud B, and Cloud C.
  - Computes the SHA3-256 hash of the reconstructed ciphertext.
  - Compares it with the blockchain ledger record: **MATCH VERIFIED**.
  - Decapsulates ML-KEM-768 ciphertext $\rightarrow$ Derives $K_{wrap}$ via HKDF $\rightarrow$ Recovers session key $\rightarrow$ Decrypts ChaCha20-Poly1305 $\rightarrow$ Delivers original file intact.

---

### Step 6: Tampering Detection Demonstration (Module 15 & 7) — High Impact!
- **Action:** On the **"My Files"** page, click the red **"Simulate Tamper"** button on an encrypted file.
- **What Happens:**
  - The system intentionally corrupts a few bytes in Cloud Provider A's fragment.
  - The system retrieves all fragments, reassembles them, and recalculates SHA3-256.
  - The calculated hash fails to match the blockchain record!
- **What to Point Out:**
  - The UI displays:
    ```
    --------------------------------
    INTEGRITY VERIFICATION
    --------------------------------
    Expected Hash (Blockchain): c8a1b2...
    Calculated Hash (Cloud):    7f3e1a...

    STATUS: TAMPERING DETECTED — DECRYPTION BLOCKED
    ```
  - Try clicking **"Download"** on that tampered file: The system refuses to decrypt and halts with a prominent security alert.

---

### Step 7: Machine Learning Threat Simulator (Module 8, 10 & 16)
- **Action:** Navigate to **"ML Threat Detection"**.
- **What to Demonstrate:**
  1. Click **"Generate Normal Activity"**:
     - Failed logins: 0, Downloads: 1, Volume: 4.5 MB, Hour: 14.
     - Result: `Prediction: NORMAL`, `Risk Score: 0.15`, `Decision: ALLOW`.
  2. Click **"Generate Suspicious Activity"**:
     - Failed logins: 8, Downloads: 45, Volume: 2.8 GB, Hour: 3 AM, New IP: 1.
     - Result: `Prediction: ANOMALY`, `Risk Score: 0.85+`, `Decision: BLOCK`.
     - Action: *"Operation blocked by AI threat detection engine. Excessive risk."*
- **Key Viva Point to State:**
  - *"We use scikit-learn Isolation Forest specifically for anomaly detection based on behavioral feature vectors. The ML model is NEVER used to generate encryption keys — cryptographic keys are generated strictly by our CSPRNG-seeded ASKG module."*

---

### Step 8: Blockchain Ledger Explorer (Module 7)
- **Action:** Click on **"Blockchain"** in the navigation bar.
- **What to Demonstrate:**
  - Inspect the cryptographic chain linking from Block #0 (Genesis Block) to all subsequent file upload blocks.
  - Show how each block references the `previous_hash` of its predecessor.
  - Click **"Verify Full Chain Cryptography"**: Demonstrates that the chain link structure is valid and untampered.

---

### Step 9: Performance Evaluation Benchmarks (Module 18 & 19)
- **Action:** Navigate to **"Performance"** and click **"Run Live Benchmark Suite"**.
- **What to Demonstrate:**
  - Show that high-precision CPU timers (`time.perf_counter`) measure actual runtime across 10 KB, 100 KB, 1 MB, 5 MB, and 10 MB payloads.
  - Highlight the Key Generation comparison table contrasting OS CSPRNG, standard HMAC-DRBG, and ASKG.
  - Emphasize that all figures are measured live without hardcoded mock data.

---

### Step 10: Structured Security Audit Logs (Module 12 & 35)
- **Action:** Navigate to **"Audit Logs"**.
- **What to Point Out:**
  - Show the chronological audit trail: `LOGIN_SUCCESS`, `KEY_GENERATED`, `FILE_ENCRYPTED`, `FILE_UPLOADED`, `HASH_VERIFIED`, `BLOCKCHAIN_TAMPER_DETECTED`.
  - Confirm that no passwords, private keys, or raw session keys appear in the logs.
