# SecureCloud-X: REST API & Route Documentation

All API endpoints are hosted by Flask and return either HTML views or JSON payloads.

---

## 1. Authentication Endpoints

### `POST /login`
- **Description:** Authenticates user via PBKDF2-HMAC-SHA256 and creates session.
- **Form Data:**
  - `username` (string, required)
  - `password` (string, required)
- **Response:** HTTP 302 Redirect to `/dashboard` on success; HTTP 200 with flash message on error.

### `GET /logout`
- **Description:** Terminates active session and records audit event.
- **Response:** HTTP 302 Redirect to `/login`.

---

## 2. File & Cryptographic Pipeline Endpoints

### `POST /upload`
- **Description:** Executes the 8-stage cryptographic upload pipeline.
- **Form Data:**
  - `file` (multipart/form-data, required)
- **Workflow:** ML behavior check $\rightarrow$ ASKG session key $\rightarrow$ ChaCha20-Poly1305 encryption $\rightarrow$ ML-KEM-768 encapsulation $\rightarrow$ HKDF key wrap $\rightarrow$ SHA3-256 hash $\rightarrow$ Blockchain block creation $\rightarrow$ Fragmentation $\rightarrow$ Cloud A/B/C distribution.
- **Response:** Renders `upload.html` with performance latencies and storage distribution metrics.

### `GET /download/<file_id>`
- **Description:** Reassembles fragments from Cloud A/B/C, checks SHA3-256 against blockchain ledger, decapsulates ML-KEM, unwraps session key, and decrypts file.
- **Response:** Binary attachment stream (`Content-Disposition: attachment`) if integrity is valid; HTTP 302 redirect with security alert if tampered or blocked by AI.

### `GET /verify-integrity/<file_id>`
- **Description:** Runs standalone SHA3-256 verification against the blockchain record.
- **Response (JSON):**
  ```json
  {
    "is_valid": true,
    "status": "INTEGRITY_VERIFIED",
    "expected_hash": "36f02858...",
    "actual_hash": "36f02858...",
    "block_index": 1,
    "message": "SHA3-256 hash matches blockchain ledger. File integrity confirmed."
  }
  ```

---

## 3. Key Generation Lab Endpoints

### `POST /api/keygen/generate`
- **Description:** Generates a new 256-bit session key via ASKG.
- **Response (JSON):**
  ```json
  {
    "success": true,
    "metadata": {
      "key_id": "KEY-0005",
      "algorithm": "HMAC-DRBG / SHA-256",
      "key_size": 256,
      "status": "Active",
      "generated_at": "2026-09-22 20:30:15",
      "reseed_count": 1
    }
  }
  ```

### `POST /api/keygen/reseed`
- **Description:** Forces explicit reseeding of HMAC-DRBG with fresh OS entropy.

### `POST /api/keygen/rotate`
- **Description:** Forces active session key rotation and updates prior keys to 'Rotated'.

---

## 4. Security & Threat Simulation Endpoints

### `POST /api/security/simulate-ml`
- **Description:** Simulates normal or suspicious user behavior against Isolation Forest.
- **Request Body (JSON):** `{"type": "normal"}` or `{"type": "suspicious"}`
- **Response (JSON):**
  ```json
  {
    "success": true,
    "simulation_type": "suspicious",
    "result": {
      "prediction": "ANOMALY",
      "risk_score": 0.85,
      "risk_level": "HIGH",
      "decision": "BLOCK",
      "action_taken": "Operation blocked by AI threat detection engine. Excessive risk."
    }
  }
  ```

### `POST /api/security/simulate-tamper`
- **Description:** Flips bytes in a fragment stored on Cloud Provider A and re-verifies.
- **Request Body (JSON):** `{"file_id": "FILE-B1C2D3E4"}`
- **Response (JSON):**
  ```json
  {
    "success": true,
    "file_id": "FILE-B1C2D3E4",
    "expected_hash": "c8a1b2...",
    "calculated_hash": "7f3e1a...",
    "status": "TAMPERING DETECTED - BLOCKED",
    "is_valid": false,
    "message": "ALERT: SHA3-256 mismatch detected! File payload has been tampered with or corrupted in cloud storage."
  }
  ```

### `GET /api/blockchain/verify-chain`
- **Description:** Traverses the entire blockchain from Genesis Block to latest, verifying all block hashes and linkage pointers.

---

## 5. Performance Benchmark Suite Endpoints

### `POST /api/performance/run-benchmark`
- **Description:** Executes live measurements for Keygen, ChaCha20, ML-KEM-768, SHA3-256, and Isolation Forest across 10KB, 100KB, 1MB, 5MB, and 10MB payloads.
- **Response (JSON):** Contains `benchmarks` array and `rng_comparison` array.
