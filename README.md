# RE-KEM — Ring-Extended Key Encapsulation Mechanism

<p align="center">
  <img src="rekem-banner.svg" alt="RE-KEM" width="100%" />
</p>

**Post-Quantum Ring-LWE Key Encapsulation Mechanism (IND-CCA2)**

A self-contained, dependency-light Python implementation of a post-quantum secure key encapsulation mechanism built on Ring-LWE in the ring ℤ₇₆₈₁[X]/(X²⁵⁶ + 1), protected by the Fujisaki–Okamoto transform (QROM-secure) and hardened with constant-time primitives.

```
██████╗ ███████╗      ██╗  ██╗███████╗███╗   ███╗
██╔══██╗██╔════╝      ██║ ██╔╝██╔════╝████╗ ████║
██████╔╝█████╗  █████╗█████═╝ █████╗  ██╔████╔██║
██╔══██╗██╔══╝  ╚════╝██╔═██╗ ██╔══╝  ██║╚██╔╝██║
██║  ██║███████╗      ██║ ╚██╗███████╗██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝      ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
──[ Post-Quantum Lattice KEM • Ring-LWE • IND-CCA2 ]──
```

```
┌─────────────────────────────────────────────────────────────────────────┐
│  RE-KEM: Ring-LWE KEM                                                   │
│  • Ring:      Z_q[X] / (X^n + 1),  n = 256, q = 7681                    │
│  • Mult:      O(n log n) via Negacyclic NTT                             │
│  • Security:  IND-CCA2 (Fujisaki–Okamoto, QROM)                         │
│  • Hardening: Constant-time sampling, decoding, rejection               │
└─────────────────────────────────────────────────────────────────────────┘
```

## ✨ Features

- **Negacyclic NTT** — polynomial multiplication in O(n log n) with precomputed twiddle tables (`ψ`, `ω`, inverse tables) for fast twisting/untwisting
- **Fujisaki–Okamoto transform** — IND-CCA2 security in the quantum random oracle model, with **implicit rejection** on invalid ciphertexts
- **Constant-time primitives** — branchless modular reduction, coefficient decoding, byte comparison and multiplexing (no secret-dependent branches)
- **Centered Binomial Distribution (CBD)** — η = 2 noise sampling via bit-popcount, deterministic from a seed
- **Pure Python + NumPy** — no external crypto libraries, no OpenSSL, fully auditable
- **Self-test suite** — key exchange verification, IND-CCA2 ciphertext-tampering test, and performance benchmark built in

## 🔐 Protocol Overview (Fujisaki–Okamoto)

```
KEM.Encaps(PK)
                    +----------------------+
                    |  m <- Random(32 B)   |
                    +----------------------+
                               |
                   G(m || H(PK)) = (K_bar, r)
                               |
         +---------------------+---------------------+
         |                                           |
         v                                           v
  c = PKE.Enc(PK, m; coins=r)               Shared Secret:
         |                                  SS = KDF(K_bar || H(c))
         +-------------------------------------------+
                                                     |
                         KEM.Decaps(SK, c)           v
                    +-------------------------+  (c, SS)
                    |  m' = PKE.Dec(sk, c)    |
                    +-------------------------+
                               |
                  G(m' || H(PK)) = (K_bar', r')
                               |
                  c' = PKE.Enc(PK, m'; coins=r')
                               |
                    +--------------------+
                    | c == c' (in O(1))? |
                    +--------------------+
                     /                  \
              [Gültig]                  [Ungültig]
                 |                          |
       SS = KDF(K_bar' || H(c))    SS = KDF(z || H(c))  (Implicit Rejection)
```

### Parameter Sizes

| Item          | Size   | Description                          |
|---------------|--------|--------------------------------------|
| `n`           | 256    | Polynomial degree (torus dimension)  |
| `q`           | 7681   | NTT-friendly prime (15·512 + 1)      |
| `η` (eta)     | 2      | CBD noise parameter                  |
| Public Key    | 544 B  | 32 B seed + 512 B polynomial `b`     |
| Secret Key    | 1120 B | 512 B `s` + PK + H(PK) + rejection `z` |
| Ciphertext    | 1024 B | `u` + `v` (2 × 512 B)                |
| Shared Secret | 32 B   | KDF output (256 bit)                 |

## 📦 Installation

```bash
# Python 3.9+ with NumPy
pip install numpy
```

No other dependencies.

## 🚀 Usage

```python
import secrets
from rekem import PostQuantumRingLWEKEM

# Instantiate the scheme
kem = PostQuantumRingLWEKEM(n=256, q=7681, eta=2)

# ── Key generation ──
pk, sk = kem.keygen()

# ── Encapsulation (sender) ──
ciphertext, shared_secret_sender = kem.encaps(pk)

# ── Decapsulation (receiver) ──
shared_secret_receiver = kem.decaps(sk, ciphertext)

assert shared_secret_sender == shared_secret_receiver
print("Shared secret established securely 🔐")
```

## 🖥️ Live Dashboard

Interactive 3D visualization of the scheme — torus lattice, NTT frequency spectrum, CBD noise histogram and the Fujisaki–Okamoto re-encryption pipeline (including a simulated bitflip attack with implicit rejection):

**→ https://cstrsk.de/RE-KEM-Dashboard/**

## 🧪 Running the Self-Test & Benchmark

```bash
python rekem.py
```

Expected output:

```
[*] Public Key Größe:  544 Bytes
[*] Secret Key Größe:  1120 Bytes
[*] Chiffrat-Größe:    1024 Bytes
[✓] Key Exchange erfolgreich!
[✓] IND-CCA2 Test bestanden: Implicit Rejection aktiv.
Performance (Python / Numpy auf 100 Durchläufen):
  KeyGen: ~3.3 ms
  Encaps: ~4.8 ms
  Decaps: ~9.5 ms (inkl. vollständiger Re-Encryption)
```

## 📊 Stresstest: 1.000.000 Schlüsselpaare

On 24 August 2026, RE-KEM passed its largest stress test: **1.000.000 key pairs** (KeyGen + Encaps + Decaps per pair) in a single run, **247.8 minutes** of continuous load at **67.3 complete key exchanges per second** — pure Python/NumPy, no C extensions, no external crypto libraries.

| Metric | Result |
|--------|--------|
| Key pairs | 1,000,000 |
| Successful roundtrips | 1,000,000 (100 %) |
| Failed roundtrips | 0 |
| Bitflip rejections (IND-CCA2) | 1,000 |
| Bitflip leaks | 0 |
| Public-key collisions | 0 |
| Throughput | 67.3 roundtrips/s (~200 crypto ops/s) |
| Duration | 247.8 min (14,866 s) |

Latency statistics (sampled, n = 10,000 per operation):

| Operation | Mean | Median | p95 | p99 | Min | Max |
|-----------|------|--------|-----|-----|-----|-----|
| KeyGen | 2.101 ms | 1.194 ms | 4.428 ms | 29.983 ms | 1.005 ms | 192.463 ms |
| Encaps | 3.810 ms | 2.260 ms | 8.410 ms | 38.157 ms | 1.865 ms | 140.314 ms |
| Decaps | 6.425 ms | 3.340 ms | 15.939 ms | 48.553 ms | 2.667 ms | 440.664 ms |

The 1,000 bitflip attacks on valid ciphertexts were all rejected via implicit rejection (0 leaks), confirming the Fujisaki–Okamoto IND-CCA2 path empirically at scale.

Verdict: **PASS** — full machine-readable analysis: [`analysis/1m-key-test.json`](analysis/1m-key-test.json)

## 🧠 Design Notes

### Negacyclic NTT with Precomputed Twiddles

The ring multiplication `a(x) · b(x) mod (xⁿ + 1)` is computed via the negacyclic NTT:

1. **Twist** both polynomials with `ψⁱ` (precomputed `psi_powers`)
2. **Forward NTT** with root `ω = ψ²`
3. **Pointwise multiply** in the frequency domain
4. **Inverse NTT** + `n⁻¹` scaling
5. **Untwist** with `ψ⁻ⁱ` (precomputed `psi_inv_powers`)

The `2n`-th primitive root of unity `ψ` is found automatically at init (`_find_primitive_root_2n`), and all twiddle tables are precomputed once for speed.

### Constant-Time Hardening

| Primitive | Purpose |
|-----------|---------|
| `_csubq` | Branchless reduction `a − q` if `a ≥ q` |
| `_ct_compare` | Ciphertext equality check without early exit (O(1)) |
| `_ct_select` | Branchless multiplexer between valid / rejected secret |
| `_ct_decode_coefficients` | Coefficient → bit decoding without secret-dependent branches |

### Security Notes

- **IND-CCA2:** The FO transform with implicit rejection prevents chosen-ciphertext attacks; any tampered ciphertext yields a pseudorandom secret derived from `z`, never the real key.
- **QROM:** `G` and `H` are modeled as quantum random oracles (SHA3-512 / SHA3-256 / SHAKE-256).
- **Parameter regime:** Ring-LWE with n = 256, q = 7681, η = 2 targets post-quantum security comparable to NIST LWE-based candidates (educational / research reference — see disclaimer).

> ⚠️ **Disclaimer:** This is a **reference / educational implementation** for studying post-quantum KEM design. It has not been independently audited and should **not** be used in production without formal security review and constant-time validation on the target platform.

## 📁 Project Structure

```
rekem.py   # Full implementation + self-test + benchmark (single file)
```

## 📄 License

**AGPL-3.0** — GNU Affero General Public License v3.0. See [LICENSE](LICENSE).

This is the CSTRSK standard license: any network service using a modified version of this software must make its source code available to its users.

## © Copyright

**CSTRSK.DE · COPYRIGHT 2008–2026** — [cstrsk.de](https://cstrsk.de) · [GitHub: CSTRSK/RE-KEM](https://github.com/CSTRSK/RE-KEM) · [Live Dashboard](https://cstrsk.de/RE-KEM-Dashboard/) · [GitHub Pages](https://cstrsk.github.io/RE-KEM/)

## 🤝 Contributing

Found a bug, a timing leak, or a way to speed up the NTT? Open an issue or PR. Performance improvements (vectorized NTT, C extensions, GPU offload) are especially welcome.
