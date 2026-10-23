# SecureCloud-X: Cryptographic & Machine Learning Algorithms

This document provides technical and mathematical explanations for each cryptographic primitive and machine learning algorithm integrated into SecureCloud-X.

---

## 1. Adaptive Secure Session Key Generator (ASKG)

### Theoretical Foundation
The ASKG module is an application-level key generator built on **NIST SP 800-90A HMAC-DRBG** using **HMAC-SHA256**. 

### Internal State & Mechanics
The DRBG maintains an internal state consisting of:
- $K$: A 32-byte secret HMAC key.
- $V$: A 32-byte working value.
- $\text{reseed\_counter}$: Counter tracking iterations since the last entropy refresh.

#### Initialization:
$$K = 0x00^{32}, \quad V = 0x01^{32}$$
$$\text{seed\_material} = \text{Entropy} \parallel \text{Nonce} \parallel \text{Personalization}$$
$$K, V \leftarrow \text{Update}(K, V, \text{seed\_material})$$

#### Update Function:
$$K \leftarrow \text{HMAC-SHA256}(K, V \parallel 0x00 \parallel \text{provided\_data})$$
$$V \leftarrow \text{HMAC-SHA256}(K, V)$$
If $\text{provided\_data} \neq \emptyset$:
$$K \leftarrow \text{HMAC-SHA256}(K, V \parallel 0x01 \parallel \text{provided\_data})$$
$$V \leftarrow \text{HMAC-SHA256}(K, V)$$

#### Entropy Collection:
Primary entropy is gathered directly from the operating system's cryptographic CSPRNG (`os.urandom(32)`). Supplementary runtime inputs (nanosecond CPU monotonic clocks and process identifiers) are mixed in to provide operational defense against VM cloning and process-fork entropy duplication.

---

## 2. Post-Quantum ML-KEM (Module-Lattice-Based KEM / FIPS 203)

### Theoretical Foundation
ML-KEM is the standardized post-quantum Key Encapsulation Mechanism derived from the CRYSTALS-Kyber submission and codified by NIST in **FIPS 203**. Its security is based on the hardness of the **Module Learning With Errors (M-LWE)** problem over polynomial rings:
$$R_q = \mathbb{Z}_q[X] / (X^{256} + 1)$$
where $q = 3329$ and degree $n = 256$.

### Parameter Set: ML-KEM-768
- **Lattice Rank ($k$):** $3$
- **Public Key Size:** $1,184$ bytes
- **Private Key Size:** $2,400$ bytes
- **Ciphertext Size:** $1,088$ bytes
- **Shared Secret Size:** $32$ bytes ($256$ bits)
- **NIST Security Category:** Category 3 (equivalent to classical AES-192 security against quantum Grover / Shor algorithms).

### Hybrid Key Encapsulation Flow:
1. **Encapsulation:** Sender inputs recipient's public key $pk_{kem}$ into $\text{ML-KEM.Encaps}(pk_{kem})$ producing:
   $$(c_{kem}, ss_{kem}) \leftarrow \text{ML-KEM.Encaps}(pk_{kem})$$
2. **KDF Expansion:** The 32-byte shared secret $ss_{kem}$ is passed through HKDF-SHA256:
   $$K_{wrap} = \text{HKDF-Extract-and-Expand}(ss_{kem}, \text{info}=\text{"SecureCloud-X-KeyWrap-v1"}, L=32)$$
3. **Session Key Wrapping:** The 256-bit ASKG file session key $K_{session}$ is encrypted under $K_{wrap}$ using ChaCha20-Poly1305.

---

## 3. ChaCha20-Poly1305 Authenticated Encryption (RFC 8439)

### Core Mechanics
ChaCha20-Poly1305 is an Authenticated Encryption with Associated Data (AEAD) algorithm:
- **ChaCha20:** A 20-round stream cipher operating on a $4 \times 4$ matrix of 32-bit words, driven by a 256-bit symmetric key, a 96-bit (12-byte) random nonce, and a 32-bit block counter.
- **Poly1305:** A high-speed cryptographic authenticator calculating a 128-bit (16-byte) MAC tag over the ciphertext and optional associated data modulo the prime $2^{130} - 5$.
- **Security:** Guarantees both confidentiality against eavesdropping and ciphertext integrity/authenticity against bit-flipping attacks.

---

## 4. SHA3-256 Cryptographic Hash (FIPS 202)

### Core Mechanics
SHA3-256 is based on the **Keccak sponge construction** featuring permutations over a state array of $5 \times 5 \times 64 = 1600$ bits:
- **Rate ($r$):** 1088 bits
- **Capacity ($c$):** 512 bits
- Unlike the MD5, SHA-1, and SHA-2 families (which use the Merkle–Damgård construction), SHA-3 is fundamentally immune to length-extension attacks. It is utilized in SecureCloud-X to compute cryptographic digests of encrypted payloads before and after multi-cloud fragmentation.

---

## 5. Isolation Forest Threat Detection (scikit-learn)

### Theoretical Foundation
Isolation Forest is an unsupervised anomaly detection algorithm that isolates anomalous observations by randomly selecting a feature and randomly selecting a split value between the minimum and maximum values of the feature.

### Rationale for Cybersecurity Application:
- Anomalies (e.g., automated credential stuffing, rapid mass data exfiltration, abnormal access hours) possess distinct attribute profiles compared to normal user baselines.
- Anomalies are separated near the roots of the isolation trees with significantly shorter path lengths $h(x)$.

### Normalized Risk Scoring Formulation:
The raw decision function score $s(x)$ is mapped to an application risk score $R \in [0.00, 1.00]$:
$$\text{If } \hat{y} = -1 \text{ (Anomaly)}: \quad R = \min\left(0.99, \, 0.70 + 1.5 \cdot |s(x)|\right)$$
$$\text{If } \hat{y} = +1 \text{ (Normal)}: \quad R = \max\left(0.05, \, 0.30 - 1.2 \cdot \max(0, s(x))\right)$$
- $R \le 0.30$: **LOW RISK** $\rightarrow$ Operation Allowed.
- $0.30 < R \le 0.70$: **MEDIUM RISK** $\rightarrow$ Operation Allowed with elevated audit logging.
- $R > 0.70$: **HIGH RISK** $\rightarrow$ Sensitive file operations halted immediately.
