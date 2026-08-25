# The History of PGP and the Evolution of Encrypted Messaging

This document accompanies the layered implementations in this repository.
Each section maps to a subdirectory under `pgp_evolution/`.

---

## Part 1: The 1991 Origins -- `pgp_evolution/classic/`

Phil Zimmermann wrote the first version of PGP (Pretty Good Privacy) in 1991
and posted it to Usenet. His stated motivation was political: the US Senate was
considering legislation that would have mandated law enforcement backdoors in all
encryption software. He wanted to get strong crypto into the public domain before
the window closed.

The export of cryptographic software was regulated as a munition under the
International Traffic in Arms Regulations (ITAR). Zimmermann did not export PGP
himself, but once it was on Usenet it crossed borders immediately. The US
government opened a criminal investigation against him that lasted three years.
It was eventually dropped, but the episode made PGP and Zimmermann famous.

**What the 1991 design used:**
- RSA for public-key operations (key sizes of 384, 512, or 1024 bits)
- IDEA (International Data Encryption Algorithm) for symmetric encryption
- MD5 for hashing
- A "web of trust" model instead of certificate authorities

The web of trust was novel: instead of a central authority vouching for keys,
users signed each other's keys, forming a distributed graph of trust. In theory
this was decentralized and resistant to single points of failure. In practice it
required users to understand what signing a key meant, which most never did.

**What was wrong with it:**
- RSA without proper padding (OAEP) is vulnerable to chosen-ciphertext attacks
- MD5 is broken for collision resistance (demonstrated by Wang et al. in 2004)
- IDEA had patent restrictions that complicated free software use
- Key IDs were 32-bit (later 64-bit), enabling trivial key spoofing attacks
- No forward secrecy: compromise of a long-lived private key decrypts all past messages
- The web of trust created a social graph attackers could map

The `classic/` implementation demonstrates this design honestly, including its
weaknesses. RSA-2048 is used (stronger than the original but same paradigm),
SHA-1 for compatibility demonstration, and ASCII armor encoding.

---

## Part 2: OpenPGP v4 and the Standardization Era -- `pgp_evolution/openpgp_v4/`

After PGP's commercial success, Zimmermann's company was acquired by Network
Associates (later PGP Corporation, later Symantec). The free software community
needed an open specification. RFC 2440 (1998) and its successor RFC 4880 (2007)
defined OpenPGP, and the GNU Privacy Guard (GPG) became its dominant open-source
implementation.

RFC 4880 improved on the original but was conservative in its choices, retaining
backward compatibility with older implementations. Version 4 keys introduced:
- SHA-1 as the primary hash (already aging by 2007)
- DSA and Elgamal alongside RSA
- Subkeys: separate signing and encryption keys under one certificate
- User IDs bound to keys via self-signatures
- Preference packets letting keys advertise which algorithms they support

The subkey design was a genuine improvement. A primary key could certify subkeys,
which could be rotated independently. This meant you did not have to generate a
new identity to change your encryption key.

**What was still wrong:**
- Algorithm negotiation was a disaster: implementations had to support old
  broken algorithms to remain interoperable
- SHA-1 fingerprints for v4 keys (160-bit, broken for collision resistance)
- 64-bit key IDs still spoonable (the "Evil32" attack in 2014 demonstrated mass
  key ID collisions on the keyserver network)
- Keyservers (SKS network) were append-only: you could upload anyone's key,
  attach unlimited signatures to poison a key, and there was no way to fully
  purge a key -- the Linus Torvalds poisoning attack in 2019 broke many GPG
  installations
- Still no forward secrecy

The `openpgp_v4/` implementation uses Ed25519 for signing, X25519 for key
agreement, and AES-256-GCM for symmetric encryption -- a modern algorithm
profile that fits within the v4 packet format.

---

## Part 3: OpenPGP v6 and RFC 9580 -- `pgp_evolution/openpgp_v6/`

RFC 9580 was published in 2024, superseding RFC 4880. It introduced version 6
keys and packets, making several long-overdue changes:

- AEAD (Authenticated Encryption with Associated Data) is mandatory, not
  optional. Supported modes: OCB, EAX, GCM.
- SHA-1 fingerprints replaced by full SHA3-256 fingerprints for v6 keys
- MD5 and SHA-1 removed from the algorithm registry
- Short key IDs removed entirely -- implementations must use full fingerprints
- Ed448 and X448 added alongside Ed25519/X25519
- Improved Symmetrically Encrypted Integrity Protected Data (SEIPD v2) packet
  that provides AEAD with chunk-based processing for streaming

This is the current standard. GPG 2.5 and Sequoia PGP (a modern Rust
implementation) have begun implementing it.

**What RFC 9580 does not fix:**
- The metadata problem: who sent what to whom and when is still visible
- Long-lived keys still provide no forward secrecy between sessions
- The web of trust model is unchanged (though many deployments have abandoned
  it in favor of key discovery via WKD or DANE)
- Complexity: the spec is still hundreds of pages

The `openpgp_v6/` implementation follows the RFC 9580 packet format precisely,
including the SEIPD v2 packet with AES-256-OCB.

---

## Part 4: The Age Approach -- `pgp_evolution/age_like/`

In 2019 Filippo Valsorda (then on the Go security team at Google) began designing
`age` as a deliberate reaction to PGP's complexity. The design goals were:

- No algorithm negotiation. One cipher suite, period.
- No key IDs, no web of trust, no signatures on keys.
- Composable with Unix pipes.
- The entire file format spec fits in a few pages.

The age format uses:
- X25519 for key agreement (ephemeral sender key per message)
- ChaCha20-Poly1305 for symmetric encryption
- HKDF-SHA256 for key derivation
- A "recipients" model: a file can be encrypted to multiple public keys, each
  getting an encrypted copy of the same file key

The stanza-based header is human-readable ASCII. There is no binary packet
format to parse.

What age deliberately omits: signing. Valsorda's position is that encryption
and signing are separate concerns and conflating them (as PGP does) causes
confusion about what each operation guarantees. If you need authenticity, sign
separately using an SSH key or a dedicated signing tool.

The `age_like/` implementation follows this design faithfully. It interoperates
with the reference `age` tool's file format.

---

## Part 5: Post-Quantum Hardening -- `pgp_evolution/pq_hybrid/`

The threat model for post-quantum cryptography is "harvest now, decrypt later":
an adversary records encrypted traffic today, then decrypts it once a
sufficiently powerful quantum computer exists. For data that must remain
confidential for decades, this is a real concern.

NIST finalized three post-quantum cryptographic standards in 2024:
- FIPS 203: ML-KEM (Module Lattice Key Encapsulation Mechanism), based on the
  Kyber submission. Used for key exchange.
- FIPS 204: ML-DSA (Module Lattice Digital Signature Algorithm), based on
  Dilithium. Used for signatures.
- FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm), based
  on SPHINCS+. Conservative signature scheme with no lattice assumptions.

The hybrid approach (X25519 + ML-KEM-768) is recommended during the transition
period. The classical and post-quantum shared secrets are combined, so an
attacker must break both to recover the file key. If ML-KEM turns out to have
a flaw, X25519 still provides classical security.

Cloudflare deployed X25519Kyber768 in TLS 1.3 in 2023. Chrome enabled it by
default in 2024. The pattern is well-established.

The `pq_hybrid/` implementation extends the age-like format with a hybrid KEM
stanza. The recipient key is a pair: an X25519 key and an ML-KEM-768 key.
The sender generates ephemeral keys for both, runs both KEMs, and combines the
shared secrets with HKDF before deriving the file key.

---

## Reading Order

1. `pgp_evolution/packets/` -- shared binary serialization primitives
2. `pgp_evolution/classic/` -- RSA + SHA-1 + IDEA-era design
3. `pgp_evolution/openpgp_v4/` -- Ed25519 + AES-GCM within the v4 packet format
4. `pgp_evolution/openpgp_v6/` -- RFC 9580 with mandatory AEAD
5. `pgp_evolution/age_like/` -- the minimalist reaction to PGP complexity
6. `pgp_evolution/pq_hybrid/` -- X25519 + ML-KEM-768 hybrid for quantum resistance

Each layer builds on ideas from the previous one. The tests in `tests/` cover
round-trip encrypt/decrypt for each layer and cross-layer compatibility where
applicable.

---

## References

- RFC 4880: OpenPGP Message Format (2007)
- RFC 9580: OpenPGP (2024)
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (2024)
- FIPS 204: Module-Lattice-Based Digital Signature Standard (2024)
- The age file format specification: https://age-encryption.org/v1
- "The PGP Problem" -- Latacora blog post on why PGP is past its prime
- Phil Zimmermann's account of the PGP export case
