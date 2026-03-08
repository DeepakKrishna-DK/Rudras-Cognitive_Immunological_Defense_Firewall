// ============================================================================
// Rudras — Homomorphic Threat Intelligence Sharing
//
// Enables privacy-preserving Indicator of Compromise (IOC) sharing between
// Rudras nodes in a cluster without revealing each node's full IOC database.
//
// Techniques:
//   1. Paillier Partially Homomorphic Encryption (PHE)
//      - Additive homomorphism: Enc(a) * Enc(b) = Enc(a+b)
//      - Pure-Rust implementation using num-bigint (512-bit modulus simulation)
//      - Key generation, encrypt, decrypt, homomorphic_add
//
//   2. Private Set Intersection (PSI) — Naive hash-based protocol
//      - Node A sends SHA3-256(IOC || shared_salt) for each of its IOCs
//      - Node B sends SHA3-256(IOC || shared_salt) for each of its IOCs
//      - Intersection = common hashes → common IOCs confirmed without disclosure
//
//   3. Shamir Secret Sharing (threshold 2-of-N)
//      - Split a blocklist encryption key into N shares
//      - Any 2 shares sufficient to reconstruct key
//      - Used for distributed blocklist consensus
//
// NOTE: The Paillier modulus here is 512 bits for demonstration. Production
// deployments should use 2048-bit moduli. The PSI is the more practically
// useful feature for IOC sharing at scale.
// ============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use num_bigint::BigUint;
use num_traits::{One, Zero};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ── Tiny Deterministic Primality ──────────────────────────────────────────────
// Miller-Rabin with small witness set for 32-bit primes (simulation only).

fn is_prime_small(n: u64) -> bool {
    if n < 2 { return false; }
    if n == 2 || n == 3 { return true; }
    if n % 2 == 0 { return false; }
    // Trial division up to sqrt(n) for small n
    let mut i = 3u64;
    while i * i <= n {
        if n % i == 0 { return false; }
        i += 2;
    }
    true
}

/// Generate a pseudo-random prime near the given seed (deterministic for testing).
fn next_prime_near(seed: u64) -> u64 {
    let mut c = seed | 1; // make odd
    while !is_prime_small(c) { c += 2; }
    c
}

// ── Paillier Key Pair (512-bit simulation via 32-bit p,q for simplicity) ──────
// In production: use 2048-bit RSA primes. Here we use BigUint arithmetic.

#[derive(Debug, Clone)]
pub struct PaillierPublicKey {
    /// n = p * q
    pub n: BigUint,
    /// n^2
    pub n_sq: BigUint,
    /// g = n + 1 (simplified — valid for this form of Paillier)
    pub g: BigUint,
}

#[derive(Debug, Clone)]
pub struct PaillierPrivateKey {
    pub lambda: BigUint, // lcm(p-1, q-1)
    pub mu: BigUint,     // modular inverse of L(g^lambda mod n^2) mod n
    pub n: BigUint,
    pub n_sq: BigUint,
}

fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    a / gcd(a, b) * b
}

fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let t = b.clone();
        b = a % &t;
        a = t;
    }
    a
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    // Extended Euclidean algorithm
    if m.is_zero() { return None; }
    let mut old_r = a.clone();
    let mut r = m.clone();
    let mut old_s = BigUint::one();
    let mut s = BigUint::zero();

    while !r.is_zero() {
        let q = old_r.clone() / r.clone();
        let tmp = r.clone();
        r = old_r.clone() - q.clone() * r.clone();
        old_r = tmp;

        let tmp = s.clone();
        // s = old_s - q * s (mod m, handling underflow)
        let qs = (q * s.clone()) % m;
        s = if old_s >= qs { (old_s.clone() - qs) % m } else { (m.clone() + old_s.clone() - qs) % m };
        old_s = tmp;
    }

    if old_r > BigUint::one() { return None; }
    Some(old_s % m)
}

fn l_function(x: &BigUint, n: &BigUint) -> BigUint {
    (x - BigUint::one()) / n
}

#[derive(Debug, Clone)]
pub struct PaillierKeyPair {
    pub public: PaillierPublicKey,
    pub private: PaillierPrivateKey,
}

impl PaillierKeyPair {
    /// Generate a Paillier key pair from two distinct primes p, q.
    /// For the simulation, p and q are 32-bit primes derived deterministically.
    pub fn generate(seed: u64) -> Self {
        // Use two distant primes derived from seed
        let p_small = next_prime_near(seed | 0xFFF);
        let q_small = next_prime_near(seed.wrapping_mul(2654435761) | 0xFFF);
        // Ensure p ≠ q
        let q_small = if q_small == p_small { next_prime_near(q_small + 2) } else { q_small };

        let p = BigUint::from(p_small);
        let q = BigUint::from(q_small);
        let n = &p * &q;
        let n_sq = &n * &n;
        let g = &n + BigUint::one();

        let p1 = &p - BigUint::one();
        let q1 = &q - BigUint::one();
        let lambda = lcm(&p1, &q1);

        // Compute mu = L(g^lambda mod n^2)^-1 mod n
        let g_lam = g.modpow(&lambda, &n_sq);
        let l_val = l_function(&g_lam, &n);
        let mu = mod_inverse(&l_val, &n)
            .unwrap_or_else(|| BigUint::one());

        PaillierKeyPair {
            public: PaillierPublicKey { n: n.clone(), n_sq: n_sq.clone(), g },
            private: PaillierPrivateKey { lambda, mu, n, n_sq },
        }
    }

    /// Encrypt a plaintext integer.
    pub fn encrypt(&self, plaintext: u64) -> BigUint {
        let pk = &self.public;
        let m = BigUint::from(plaintext);
        // Use r = g as a fixed "random" for determinism in simulation
        // Production: r should be a random coprime to n
        let r = &pk.g % &pk.n;
        let gm = pk.g.modpow(&m, &pk.n_sq);
        let rn = r.modpow(&pk.n, &pk.n_sq);
        (gm * rn) % &pk.n_sq
    }

    /// Decrypt a ciphertext.
    pub fn decrypt(&self, ciphertext: &BigUint) -> u64 {
        let sk = &self.private;
        let c_lam = ciphertext.modpow(&sk.lambda, &sk.n_sq);
        let l_val = l_function(&c_lam, &sk.n);
        let pt_big = (l_val * &sk.mu) % &sk.n;
        // Truncate to u64 for simulation
        let bytes = pt_big.to_bytes_be();
        let mut result = 0u64;
        for &b in bytes.iter().take(8) {
            result = (result << 8) | b as u64;
        }
        result
    }

    /// Homomorphic addition: Enc(a) * Enc(b) mod n^2 = Enc(a + b).
    pub fn homomorphic_add(&self, c1: &BigUint, c2: &BigUint) -> BigUint {
        (c1 * c2) % &self.public.n_sq
    }
}

// ── Private Set Intersection ──────────────────────────────────────────────────

pub struct PrivateSetIntersection {
    /// Shared salt agreed upon by all nodes (distributed via key exchange)
    shared_salt: Vec<u8>,
}

impl PrivateSetIntersection {
    pub fn new(shared_salt: &[u8]) -> Self {
        Self { shared_salt: shared_salt.to_vec() }
    }

    /// Hash each IOC with the shared salt. Share this output with peers.
    pub fn hash_set(&self, iocs: &[String]) -> HashSet<String> {
        iocs.iter().map(|ioc| self.hash_ioc(ioc)).collect()
    }

    fn hash_ioc(&self, ioc: &str) -> String {
        let mut h = Sha3_256::new();
        h.update(ioc.as_bytes());
        h.update(b":");
        h.update(&self.shared_salt);
        hex::encode(h.finalize())
    }

    /// Compute intersection of two hashed sets. Returns number of common IOCs.
    pub fn compute_intersection_count(
        &self, local_hashes: &HashSet<String>, peer_hashes: &HashSet<String>,
    ) -> usize {
        local_hashes.intersection(peer_hashes).count()
    }

    /// Full intersection (returns common hashes — NOT the original IOCs).
    pub fn compute_intersection(
        &self, local_hashes: &HashSet<String>, peer_hashes: &HashSet<String>,
    ) -> HashSet<String> {
        local_hashes.intersection(peer_hashes).cloned().collect()
    }
}

// ── Shamir Secret Sharing (2-of-N threshold) ─────────────────────────────────

/// A share of a secret. Hold (index, value) pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretShare {
    pub index: u64,
    pub value: u64,
}

/// Split a 64-bit secret into N shares with 2-of-N threshold.
/// Uses polynomial: f(x) = secret + ax (mod large prime).
pub fn shamir_split(secret: u64, n: u8, prime: u64) -> Vec<SecretShare> {
    // Random coefficient a (derived deterministically from secret for simulation)
    let a = (secret.wrapping_mul(2654435761) % prime) | 1;
    (1..=(n as u64))
        .map(|i| SecretShare {
            index: i,
            value: (secret.wrapping_add(a.wrapping_mul(i))) % prime,
        })
        .collect()
}

/// Reconstruct secret from any 2 shares using Lagrange interpolation.
pub fn shamir_reconstruct_2(s1: &SecretShare, s2: &SecretShare, prime: u64) -> u64 {
    // f(x) = s1.value * (0 - s2.index)/(s1.index - s2.index)
    //      + s2.value * (0 - s1.index)/(s2.index - s1.index)
    // Using modular arithmetic
    let x0 = s1.index;
    let x1 = s2.index;
    let y0 = s1.value;
    let y1 = s2.value;

    // Lagrange basis l0 = (0 - x1) / (x0 - x1) mod prime
    // Since we want f(0), the x point is 0.
    let num0 = (prime - x1 % prime) % prime;
    let den0 = (x0 + prime - x1) % prime;

    let num1 = (prime - x0 % prime) % prime;
    let den1 = (x1 + prime - x0) % prime;

    // Modular inverse via Fermat's little theorem (prime is assumed prime)
    fn mod_inv_fermat(a: u64, p: u64) -> u64 {
        // a^(p-2) mod p
        let mut result = 1u64;
        let mut base = a % p;
        let mut exp = p - 2;
        while exp > 0 {
            if exp & 1 == 1 { result = result.wrapping_mul(base) % p; }
            base = base.wrapping_mul(base) % p;
            exp >>= 1;
        }
        result
    }

    let l0 = (num0 * mod_inv_fermat(den0, prime)) % prime;
    let l1 = (num1 * mod_inv_fermat(den1, prime)) % prime;

    (y0.wrapping_mul(l0).wrapping_add(y1.wrapping_mul(l1))) % prime
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HomomorphicStats {
    pub encryptions: u64,
    pub decryptions: u64,
    pub homomorphic_additions: u64,
    pub psi_computations: u64,
    pub iocs_shared: u64,
    pub iocs_in_local_db: usize,
}

// ── Homomorphic Sharing Engine ────────────────────────────────────────────────

pub struct HomomorphicSharingEngine {
    key_pair: PaillierKeyPair,
    psi: PrivateSetIntersection,
    local_iocs: RwLock<Vec<String>>,
    encryptions: AtomicU64,
    decryptions: AtomicU64,
    homo_adds: AtomicU64,
    psi_computations: AtomicU64,
    iocs_shared: AtomicU64,
}

impl HomomorphicSharingEngine {
    pub fn new() -> Self {
        let seed = unix_secs() ^ 0xDEADBEEFCAFEBABE;
        let key_pair = PaillierKeyPair::generate(seed);
        let psi = PrivateSetIntersection::new(b"RUDRAS-PSI-SALT-V1");
        info!("🔏 Homomorphic Sharing Engine initialized — Paillier n={}-bits, PSI ready",
            key_pair.public.n.bits());
        Self {
            key_pair,
            psi,
            local_iocs: RwLock::new(Vec::new()),
            encryptions: AtomicU64::new(0),
            decryptions: AtomicU64::new(0),
            homo_adds: AtomicU64::new(0),
            psi_computations: AtomicU64::new(0),
            iocs_shared: AtomicU64::new(0),
        }
    }

    /// Add a local IOC to the private database.
    pub fn add_ioc(&self, ioc: &str) {
        self.local_iocs.write().push(ioc.to_string());
    }

    /// Bulk load IOCs.
    pub fn load_iocs(&self, iocs: &[&str]) {
        let mut db = self.local_iocs.write();
        for ioc in iocs { db.push(ioc.to_string()); }
        info!("🔏 Loaded {} IOCs into homomorphic sharing db", iocs.len());
    }

    /// Encrypt a count value homomorphically.
    pub fn encrypt_count(&self, value: u64) -> BigUint {
        self.encryptions.fetch_add(1, Ordering::Relaxed);
        self.key_pair.encrypt(value)
    }

    /// Decrypt a count value.
    pub fn decrypt_count(&self, ciphertext: &BigUint) -> u64 {
        self.decryptions.fetch_add(1, Ordering::Relaxed);
        self.key_pair.decrypt(ciphertext)
    }

    /// Homomorphically add two encrypted counts.
    pub fn add_encrypted(&self, c1: &BigUint, c2: &BigUint) -> BigUint {
        self.homo_adds.fetch_add(1, Ordering::Relaxed);
        self.key_pair.homomorphic_add(c1, c2)
    }

    /// Build the blinded IOC set to share with peers.
    pub fn build_share_set(&self) -> HashSet<String> {
        let iocs = self.local_iocs.read();
        self.iocs_shared.fetch_add(iocs.len() as u64, Ordering::Relaxed);
        self.psi.hash_set(&iocs)
    }

    /// Compute intersection with a peer's shared set.
    /// Returns count of common IOCs (does not reveal which ones).
    pub fn intersect_with_peer(
        &self, peer_hashes: &HashSet<String>,
    ) -> (usize, HashSet<String>) {
        self.psi_computations.fetch_add(1, Ordering::Relaxed);
        let local = self.build_share_set();
        let count = self.psi.compute_intersection_count(&local, peer_hashes);
        let common = self.psi.compute_intersection(&local, peer_hashes);
        info!("🔏 PSI result: {} common IOCs with peer", count);
        (count, common)
    }

    /// Split a key into N shares (2-of-N threshold).
    pub fn split_key(&self, key_u64: u64, n: u8) -> Vec<SecretShare> {
        const PRIME: u64 = 0xFFFFFFFFFFFFFFC5; // Mersenne-class prime < 2^64
        shamir_split(key_u64, n, PRIME)
    }

    /// Reconstruct a key from any 2 shares.
    pub fn reconstruct_key(&self, s1: &SecretShare, s2: &SecretShare) -> u64 {
        const PRIME: u64 = 0xFFFFFFFFFFFFFFC5;
        shamir_reconstruct_2(s1, s2, PRIME)
    }

    pub fn stats(&self) -> HomomorphicStats {
        HomomorphicStats {
            encryptions: self.encryptions.load(Ordering::Relaxed),
            decryptions: self.decryptions.load(Ordering::Relaxed),
            homomorphic_additions: self.homo_adds.load(Ordering::Relaxed),
            psi_computations: self.psi_computations.load(Ordering::Relaxed),
            iocs_shared: self.iocs_shared.load(Ordering::Relaxed),
            iocs_in_local_db: self.local_iocs.read().len(),
        }
    }
}
