# SecureCloud-X: Automated Testing Documentation

SecureCloud-X incorporates an automated unit test suite built with Python's standard `unittest` framework. All tests can be executed with a single command:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 1. Test Suite Matrix

| Test Suite | Test File | Test Case Name | Objective / Description | Expected Result |
| :--- | :--- | :--- | :--- | :--- |
| **Cryptography** | `tests/test_crypto.py` | `test_chacha20_roundtrip` | Verifies ChaCha20-Poly1305 encryption & decryption cycle. | `PASS` (Plaintext recovered identically) |
| **Cryptography** | `tests/test_crypto.py` | `test_chacha20_tamper_fails` | Verifies that ciphertext bit-flips raise `InvalidTag`. | `PASS` (Decryption aborted) |
| **Cryptography** | `tests/test_crypto.py` | `test_mlkem_encapsulation_decapsulation` | Tests ML-KEM-768 keypair generation, encapsulation, and decapsulation. | `PASS` (Shared secret match) |
| **Cryptography** | `tests/test_crypto.py` | `test_hkdf_wrapping_roundtrip` | Verifies HKDF-SHA256 derivation and ChaCha20 session key wrapping. | `PASS` (Session key unwrap matches original) |
| **Cryptography** | `tests/test_crypto.py` | `test_sha3_256_integrity` | Tests SHA3-256 calculation and constant-time match verification. | `PASS` (Match on identical, False on altered) |
| **Integrity Ledger** | `tests/test_integrity.py` | `test_block_hash_calculation` | Validates block header concatenation and SHA-256 hash. | `PASS` (Hash changes upon header alteration) |
| **Integrity Ledger** | `tests/test_integrity.py` | `test_chain_verification_and_tamper_detection` | Validates linked-list hash pointers across blockchain blocks. | `PASS` (Full chain valid) |
| **Integrity Ledger** | `tests/test_integrity.py` | `test_file_integrity_tampering_check` | Simulates cloud corruption and tests `verify_file_integrity`. | `PASS` (`TAMPERING_DETECTED` on mismatch) |
| **Key Generation** | `tests/test_key_generation.py` | `test_hmac_drbg_state` | Validates internal state initialization ($K, V$) and generation. | `PASS` (Consecutive outputs independent) |
| **Key Generation** | `tests/test_key_generation.py` | `test_askg_generation_and_uniqueness` | Generates 100 consecutive 256-bit keys and tests set uniqueness. | `PASS` (100 unique keys, 0 collisions) |
| **Key Generation** | `tests/test_key_generation.py` | `test_askg_reseed_and_rotation` | Validates OS entropy injection and active key status transitions. | `PASS` (Reseed count increments, status updated) |
| **Machine Learning** | `tests/test_ml.py` | `test_normal_behavior_classification` | Evaluates baseline feature vector against Isolation Forest. | `PASS` (`NORMAL`, risk score $\le 0.70$, `ALLOW`) |
| **Machine Learning** | `tests/test_ml.py` | `test_anomalous_behavior_blocking` | Evaluates exfiltration profile with high failures and volume. | `PASS` (`ANOMALY`, risk score $> 0.70$, `BLOCK`) |
| **Storage Simulation** | `tests/test_storage.py` | `test_fragmentation_and_reassembly` | Splits 15 KB binary into 3 chunks and tests reassembly. | `PASS` (Reassembled payload matches original) |
| **Storage Simulation** | `tests/test_storage.py` | `test_multi_cloud_distribution_and_retrieval` | Stores fragments into Cloud A, B, C and reconstructs stream. | `PASS` (End-to-end retrieval successful) |

---

## 2. Test Execution Output

```
test_chacha20_roundtrip (test_crypto.TestCryptoPipeline.test_chacha20_roundtrip) ... ok
test_chacha20_tamper_fails (test_crypto.TestCryptoPipeline.test_chacha20_tamper_fails) ... ok
test_hkdf_wrapping_roundtrip (test_crypto.TestCryptoPipeline.test_hkdf_wrapping_roundtrip) ... ok
test_mlkem_encapsulation_decapsulation (test_crypto.TestCryptoPipeline.test_mlkem_encapsulation_decapsulation) ... ok
test_sha3_256_integrity (test_crypto.TestCryptoPipeline.test_sha3_256_integrity) ... ok
test_block_hash_calculation (test_integrity.TestIntegrityLedger.test_block_hash_calculation) ... ok
test_chain_verification_and_tamper_detection (test_integrity.TestIntegrityLedger.test_chain_verification_and_tamper_detection) ... ok
test_file_integrity_tampering_check (test_integrity.TestIntegrityLedger.test_file_integrity_tampering_check) ... ok
test_askg_generation_and_uniqueness (test_key_generation.TestKeyGeneration.test_askg_generation_and_uniqueness) ... ok
test_askg_reseed_and_rotation (test_key_generation.TestKeyGeneration.test_askg_reseed_and_rotation) ... ok
test_hmac_drbg_state (test_key_generation.TestKeyGeneration.test_hmac_drbg_state) ... ok
test_anomalous_behavior_blocking (test_ml.TestMLThreatDetector.test_anomalous_behavior_blocking) ... ok
test_normal_behavior_classification (test_ml.TestMLThreatDetector.test_normal_behavior_classification) ... ok
test_fragmentation_and_reassembly (test_storage.TestStorageSimulation.test_fragmentation_and_reassembly) ... ok
test_multi_cloud_distribution_and_retrieval (test_storage.TestStorageSimulation.test_multi_cloud_distribution_and_retrieval) ... ok

----------------------------------------------------------------------
Ran 15 tests in 4.002s

OK
```
