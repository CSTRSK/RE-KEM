"""Ring-Extended Key Encapsulation Mechanism

Post-Quantum Ring-LWE Key Encapsulation Mechanism (RE-KEM)
- Ring: Z_q[X] / (X^n + 1) mit n=256, q=7681
- Multiplikation: O(n log n) via Negacyclic NTT
- Sicherheit: IND-CCA2 via Fujisaki-Okamoto Transform (QROM-sicher)
- Timing-Schutz: Constant-Time Sampling, Decoding und Rejection
"""

import numpy as np
import hashlib
import secrets
import time


class PostQuantumRingLWEKEM:
    def __init__(self, n: int = 256, q: int = 7681, eta: int = 2):
        self.n = n          # Polynomgrad (Dimension des Torus)
        self.q = q          # Primzahl-Modulus: 7681 = 15 * 512 + 1 (NTT-freundlich)
        self.eta = eta      # CBD-Rauschparameter

        # Precomputations für negazyklische NTT
        self.psi = self._find_primitive_root_2n()
        self.psi_inv = pow(self.psi, -1, self.q)
        self.omega = pow(self.psi, 2, self.q)
        self.omega_inv = pow(self.omega, -1, self.q)
        self.n_inv = pow(self.n, -1, self.q)

        # Tabellen für schnelles Twisting / Untwisting
        self.psi_powers = np.array([pow(self.psi, i, self.q) for i in range(self.n)], dtype=np.int64)
        self.psi_inv_powers = np.array([pow(self.psi_inv, i, self.q) for i in range(self.n)], dtype=np.int64)

    # =========================================================================
    # 1. Constant-Time Arithmetik & Bitmask-Operationen
    # =========================================================================

    @staticmethod
    def _csubq(a: int, q: int) -> int:
        """Zieht q ab, falls a >= q (Branchless)."""
        diff = a - q
        mask = diff >> 63  # -1 wenn a < q, 0 wenn a >= q
        return diff + (mask & q)

    @staticmethod
    def _ct_compare(a: bytes, b: bytes) -> int:
        """Gibt 0 zurück wenn a == b, sonst 1 (Constant-Time)."""
        if len(a) != len(b):
            return 1
        diff = 0
        for x, y in zip(a, b):
            diff |= (x ^ y)
        return (diff | -diff) >> 31 & 1

    @staticmethod
    def _ct_select(mask: int, a: bytes, b: bytes) -> bytes:
        """Wählt b wenn mask=1, wählt a wenn mask=0 (Branchless Multiplexer)."""
        res = bytearray(len(a))
        m = -mask & 0xFF
        for i in range(len(a)):
            res[i] = (a[i] & ~m) | (b[i] & m)
        return bytes(res)

    def _ct_decode_coefficients(self, w: np.ndarray) -> bytes:
        """Dekodiert Torus-Koeffizienten branchless zu 32 Bytes (256 Bits)."""
        dec_bits = np.zeros(self.n, dtype=np.uint8)
        half_q = self.q // 2
        quarter_q = self.q // 4

        for i in range(self.n):
            val = int(w[i]) % self.q
            # Zentrieren um 0: [-q/2, q/2]
            mask_high = -((val - (half_q + 1)) >> 63 ^ 1) & 0xFFFFFFFFFFFFFFFF
            val_centered = val - (mask_high & self.q)

            # Absoluter Betrag ohne Verzweigung: abs(x) = (x ^ sign) - sign
            sign = val_centered >> 63
            abs_val = (val_centered ^ sign) - sign

            # Schwellenwert: Ist abs_val > q/4?
            diff = quarter_q - abs_val
            dec_bits[i] = (diff >> 63) & 1

        return np.packbits(dec_bits).tobytes()

    # =========================================================================
    # 2. Negazyklische NTT (O(n log n) Multiplikation)
    # =========================================================================

    def _find_primitive_root_2n(self) -> int:
        target_order = 2 * self.n
        for g in range(2, self.q):
            if pow(g, (self.q - 1) // 2, self.q) == self.q - 1:
                cand = pow(g, (self.q - 1) // target_order, self.q)
                if pow(cand, self.n, self.q) == self.q - 1:
                    return cand
        raise ValueError("Keine 2n-te Einheitswurzel gefunden.")

    def _ntt(self, poly: np.ndarray, root: int) -> np.ndarray:
        """Radix-2 Cooley-Tukey NTT mit Bit-Reversal."""
        a = list(poly)
        n = len(a)
        j = 0
        for i in range(1, n):
            bit = n >> 1
            while j & bit:
                j ^= bit
                bit >>= 1
            j ^= bit
            if i < j:
                a[i], a[j] = a[j], a[i]

        length = 2
        while length <= n:
            wlen = pow(root, n // length, self.q)
            for i in range(0, n, length):
                w = 1
                for k in range(length // 2):
                    u = a[i + k]
                    v = (a[i + k + length // 2] * w) % self.q
                    a[i + k] = (u + v) % self.q
                    a[i + k + length // 2] = (u - v) % self.q
                    w = (w * wlen) % self.q
            length <<= 1
        return np.array(a, dtype=np.int64)

    def _poly_mul_ntt(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Negazyklische Faltung modulo (X^n + 1) in O(n log n)."""
        # 1. Twisting mit psi^i
        a_tw = (a * self.psi_powers) % self.q
        b_tw = (b * self.psi_powers) % self.q

        # 2. Vorwärts-NTT
        a_hat = self._ntt(a_tw, self.omega)
        b_hat = self._ntt(b_tw, self.omega)

        # 3. Punktweises Produkt
        c_hat = (a_hat * b_hat) % self.q

        # 4. Inverse NTT & Untwisting
        c_tw = (self._ntt(c_hat, self.omega_inv) * self.n_inv) % self.q
        return (c_tw * self.psi_inv_powers) % self.q

    # =========================================================================
    # 3. Sampling & Serialisierung
    # =========================================================================

    def _cbd_sample(self, seed: bytes, nonce: int) -> np.ndarray:
        """Constant-Time Centered Binomial Distribution (eta=2) via Bit-Popcount."""
        raw_bytes = hashlib.shake_256(seed + bytes([nonce])).digest(self.n * 2)
        coeffs = []
        for i in range(0, len(raw_bytes), 4):
            chunk = int.from_bytes(raw_bytes[i:i + 4], byteorder="little")
            d = (chunk & 0x55555555) + ((chunk >> 1) & 0x55555555)
            for j in range(8):
                a = (d >> (4 * j)) & 0x3
                b = (d >> (4 * j + 2)) & 0x3
                coeffs.append(a - b)
        return np.array(coeffs[:self.n], dtype=np.int64)

    def _expand_a(self, seed: bytes) -> np.ndarray:
        """Deterministische Expansion des öffentlichen Polynoms a(x) aus 32 Bytes."""
        raw = hashlib.shake_256(seed).digest(self.n * 2)
        poly = np.zeros(self.n, dtype=np.int64)
        for i in range(self.n):
            poly[i] = (raw[2 * i] | (raw[2 * i + 1] << 8)) % self.q
        return poly

    def _encode_poly(self, poly: np.ndarray) -> bytes:
        """Packt Koeffizienten in Byte-Repräsentation (2 Bytes pro Koeffizient)."""
        buf = bytearray(self.n * 2)
        for i in range(self.n):
            v = int(poly[i]) % self.q
            buf[2 * i] = v & 0xFF
            buf[2 * i + 1] = (v >> 8) & 0xFF
        return bytes(buf)

    def _decode_poly(self, data: bytes) -> np.ndarray:
        poly = np.zeros(self.n, dtype=np.int64)
        for i in range(self.n):
            poly[i] = data[2 * i] | (data[2 * i + 1] << 8)
        return poly

    # =========================================================================
    # 4. Underlying Deterministic PKE (CPAPKE)
    # =========================================================================

    def _pke_encrypt(self, pk_bytes: bytes, msg_bytes: bytes, coins: bytes) -> bytes:
        seed_a = pk_bytes[:32]
        b = self._decode_poly(pk_bytes[32:])
        a = self._expand_a(seed_a)

        # Ephemere Terme deterministisch aus 'coins'
        r = self._cbd_sample(coins, nonce=0)
        e1 = self._cbd_sample(coins, nonce=1)
        e2 = self._cbd_sample(coins, nonce=2)

        # 32 Byte Klartext als Amplituden (q/2) auf das Torus-Polynom aufmodulieren
        msg_bits = np.unpackbits(np.frombuffer(msg_bytes, dtype=np.uint8))
        msg_poly = (msg_bits.astype(np.int64) * (self.q // 2)) % self.q

        # u(x) = a(x)*r(x) + e1(x) | v(x) = b(x)*r(x) + e2(x) + msg(x)
        u = (self._poly_mul_ntt(a, r) + e1) % self.q
        v = (self._poly_mul_ntt(b, r) + e2 + msg_poly) % self.q

        return self._encode_poly(u) + self._encode_poly(v)

    def _pke_decrypt(self, s: np.ndarray, ct_bytes: bytes) -> bytes:
        half_len = self.n * 2
        u = self._decode_poly(ct_bytes[:half_len])
        v = self._decode_poly(ct_bytes[half_len:])

        # w(x) = v(x) - u(x)*s(x)
        w = (v - self._poly_mul_ntt(u, s)) % self.q
        return self._ct_decode_coefficients(w)

    # =========================================================================
    # 5. Public API: Fujisaki-Okamoto KEM (IND-CCA2)
    # =========================================================================

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Generiert ein IND-CCA2 KEM Schlüsselpaar.
        Returns:
            pk: 544 Bytes (32B Seed + 512B Polynom b)
            sk: 1120 Bytes (512B s + 544B PK + 32B H(PK) + 32B z)
        """
        seed_a = secrets.token_bytes(32)
        noise_seed = secrets.token_bytes(32)
        z = secrets.token_bytes(32)  # Reject-Secret für Implicit Rejection

        a = self._expand_a(seed_a)
        s = self._cbd_sample(noise_seed, nonce=0)
        e = self._cbd_sample(noise_seed, nonce=1)

        b = (self._poly_mul_ntt(a, s) + e) % self.q

        pk = seed_a + self._encode_poly(b)
        h_pk = hashlib.sha3_256(pk).digest()

        sk = self._encode_poly(s) + pk + h_pk + z
        return pk, sk

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        """
        Kapselt ein 256-Bit Shared Secret für den Public Key.
        Returns:
            ciphertext: 1024 Bytes (u, v)
            shared_secret: 32 Bytes
        """
        m = secrets.token_bytes(32)
        h_pk = hashlib.sha3_256(pk).digest()

        # (K_bar, coins) = G(m || H(PK))
        g_out = hashlib.sha3_512(m + h_pk).digest()
        k_bar, coins = g_out[:32], g_out[32:]

        # Chiffrat deterministisch generieren
        ciphertext = self._pke_encrypt(pk, m, coins)

        # Shared Secret = KDF(K_bar || H(c))
        h_c = hashlib.sha3_256(ciphertext).digest()
        shared_secret = hashlib.shake_256(k_bar + h_c).digest(32)

        return ciphertext, shared_secret

    def decaps(self, sk: bytes, ciphertext: bytes) -> bytes:
        """
        Dekapselt das Shared Secret mit vollständiger Re-Encryption & Implicit Rejection.
        """
        poly_bytes = self.n * 2
        pk_bytes_len = 32 + poly_bytes

        # SK-Segmente entpacken
        s = self._decode_poly(sk[:poly_bytes])
        offset = poly_bytes
        pk = sk[offset: offset + pk_bytes_len]
        offset += pk_bytes_len
        h_pk = sk[offset: offset + 32]
        offset += 32
        z = sk[offset: offset + 32]

        # 1. Plaintext-Kandidat entschlüsseln
        m_prime = self._pke_decrypt(s, ciphertext)

        # 2. Re-Encryption Parameter ableiten
        g_out = hashlib.sha3_512(m_prime + h_pk).digest()
        k_bar_prime, coins_prime = g_out[:32], g_out[32:]

        # 3. Chiffrat neu berechnen
        ct_prime = self._pke_encrypt(pk, m_prime, coins_prime)

        # 4. Constant-Time Gleichheitsprüfung
        fail = self._ct_compare(ciphertext, ct_prime)

        # 5. Shared Secret Ableitung (Valid vs. Implicit Rejection)
        h_c = hashlib.sha3_256(ciphertext).digest()
        ss_success = hashlib.shake_256(k_bar_prime + h_c).digest(32)
        ss_fail = hashlib.shake_256(z + h_c).digest(32)

        # Branchless Multiplexing
        return self._ct_select(fail, ss_success, ss_fail)


# =========================================================================
# Verifikation, Sicherheitsanalyse und Performance-Benchmark
# =========================================================================

if __name__ == "__main__":
    print("=" * 65)
    print("Post-Quantum Ring-LWE KEM (IND-CCA2) – Integrationsprüfung")
    print("=" * 65)

    kem = PostQuantumRingLWEKEM(n=256, q=7681, eta=2)

    # 1. Schlüsselgenerierung
    pk, sk = kem.keygen()
    print(f"[*] Public Key Größe:  {len(pk)} Bytes")
    print(f"[*] Secret Key Größe:  {len(sk)} Bytes")

    # 2. Kapselung / Dekapselung
    ct, ss_sender = kem.encaps(pk)
    print(f"[*] Chiffrat-Größe:    {len(ct)} Bytes")

    ss_receiver = kem.decaps(sk, ct)
    assert ss_sender == ss_receiver, "FEHLER: Schlüssel stimmen nicht überein!"
    print(f"[✓] Key Exchange erfolgreich!")
    print(f"    Shared Secret: {ss_sender.hex()[:32]}... (32 Bytes)")

    # 3. IND-CCA2 Validierung (Angriffstest auf Chiffrat-Integrität)
    corrupted_ct = bytearray(ct)
    corrupted_ct[100] ^= 0x01  # Bitflip im Chiffrat
    corrupted_ct = bytes(corrupted_ct)

    ss_corrupted = kem.decaps(sk, corrupted_ct)
    assert ss_corrupted != ss_sender, "SICHERHEITSLECKS: Manipuliertes Chiffrat lieferte Key!"
    print(f"[✓] IND-CCA2 Test bestanden: Implicit Rejection aktiv.")
    print(f"    Manipuliertes Secret: {ss_corrupted.hex()[:32]}... (Pseudo-Random)")

    # 4. Benchmark
    rounds = 100
    t0 = time.perf_counter()
    for _ in range(rounds):
        _pk, _sk = kem.keygen()
    t_keygen = (time.perf_counter() - t0) / rounds * 1000

    t0 = time.perf_counter()
    for _ in range(rounds):
        _ct, _ss = kem.encaps(pk)
    t_encaps = (time.perf_counter() - t0) / rounds * 1000

    t0 = time.perf_counter()
    for _ in range(rounds):
        _ = kem.decaps(sk, ct)
    t_decaps = (time.perf_counter() - t0) / rounds * 1000

    print("\n" + "=" * 65)
    print(f"Performance (Python / Numpy auf {rounds} Durchläufen):")
    print(f"  KeyGen: {t_keygen:.2f} ms")
    print(f"  Encaps: {t_encaps:.2f} ms")
    print(f"  Decaps: {t_decaps:.2f} ms (inkl. vollständiger Re-Encryption)")
    print("=" * 65)
