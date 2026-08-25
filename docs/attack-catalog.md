# Attack Catalog

A chronological catalog of attacks on PGP and OpenPGP, what they exploit, and
which layer in this project addresses each one.

The point is not to catalog every CVE. It is to show that most of these attacks
were predictable from the design -- the algorithms and constructions chosen in
1991 and 2007 had known weaknesses that were deferred rather than fixed.

---

## 1. PKCS#1 v1.5 Bleichenbacher Attack (1998)

**What it exploits.** RSA encryption with PKCS#1 v1.5 padding leaks whether
the decrypted padding is valid. An attacker who can submit ciphertexts and
observe whether decryption succeeds (even as a timing difference or error
message difference) can use this as an adaptive chosen-ciphertext oracle.
With roughly one million queries the full plaintext is recovered.

**Why PGP was affected.** The original PGP used RSA with PKCS#1 v1.5 for
session key encryption. Any implementation that returned a different error for
"bad padding" versus "bad session key" was an oracle.

**Mitigation.** RSA-OAEP (Optimal Asymmetric Encryption Padding) removes the
padding oracle by making all failure modes indistinguishable. RFC 4880 section
13.1 specifies OAEP for RSA in OpenPGP but implementations were slow to adopt
it. The `classic` layer in this project uses OAEP. If you want to demonstrate
the v1.5 attack, you need to implement a separate oracle server.

**Fixed in.** v4 layer (ECDH replaces RSA entirely).

---

## 2. Mister-Zuccherato: Unauthenticated Symmetric Encryption (2005)

**What it exploits.** OpenPGP's Symmetrically Encrypted Data packet (tag 9)
uses CFB mode with no MAC. An attacker who can observe whether decryption
produces valid output can mount a chosen-ciphertext attack. The attack exploits
a specific property of the OpenPGP CFB "resync" mechanism where the first two
bytes of the ciphertext are used to verify the session key. By manipulating
these bytes and observing whether the recipient rejects the message, the
attacker gradually recovers the plaintext.

The attack requires access to a decryption oracle -- typically someone who will
decrypt and return an error message. In practice this was the "Does it fail with
bad session key or bad padding?" oracle.

**Why PGP was affected.** Tag 9 SED packets with no integrity check were the
default in GPG until the MDC packet (tag 19) was introduced. Worse, many
implementations would fall back to tag 9 when the recipient's key did not
advertise MDC support, creating a downgrade path.

**Mitigation.** The Symmetrically Encrypted Integrity Protected Data packet
(SEIPD, tag 18) appends an SHA-1 MDC (Modification Detection Code). This
detects ciphertext modification before decryption output is returned, removing
the oracle. The `openpgp_v4` layer uses SEIPD v1. The `openpgp_v6` layer uses
SEIPD v2 with full AEAD, which is stronger.

**Fixed in.** v4 layer (SEIPD v1). Fully fixed in v6 (SEIPD v2 mandatory AEAD).

---

## 3. SHA-1 Collision Attacks (Wang et al., 2004 -- SHAttered, 2017)

**What it exploits.** SHA-1's compression function has structural weaknesses
that allow chosen-prefix collision attacks. In 2017 the SHAttered attack
produced two PDFs with the same SHA-1 hash for approximately 2^63 operations,
far below the 2^80 theoretical collision resistance.

**Why PGP was affected.** OpenPGP v4 fingerprints are SHA-1 hashes of the
public key packet body. Two different public keys with the same SHA-1 fingerprint
are indistinguishable by fingerprint. An attacker who can create a collision key
pair can impersonate a known identity.

In practice, OpenPGP collision attacks are harder than document collision attacks
because the attacker must control both keys in the collision. But the theoretical
attack surface is real.

SHA-1 was also used as the default hash in v4 self-signatures, binding user IDs
to keys. A forged self-signature on a malicious user ID is a viable attack if
SHA-1 can be collided.

**Mitigation.** RFC 9580 v6 fingerprints use SHA3-256. SHA-3 has a completely
different internal structure (sponge construction) from SHA-1 and SHA-2 and is
not affected by the length-extension or differential attacks that broke SHA-1.

**Fixed in.** v6 layer (SHA3-256 fingerprints).

---

## 4. Short Key ID Spoofing -- Evil32 (2014)

**What it exploits.** OpenPGP v4 key IDs are 32 bits (the low 32 bits of the
64-bit key ID). GPG and many keyserver UIs displayed only the short 32-bit key
ID by default. An attacker can generate keys until one collides with a target
key ID. On 2014 hardware, birthday collisions for 32-bit IDs take seconds. The
Evil32 project generated colliding keys for every key in the strong set to
demonstrate this.

The 64-bit key ID is better but still vulnerable: birthday attacks require only
2^32 key generations to find a collision with a specific target, achievable with
a few days of CPU time.

**Impact.** Anyone who fetched a key by short ID from a keyserver could receive
an attacker's key instead of the intended key. The attacker's key could then
sign malicious software while appearing to match the expected key ID.

**Mitigation.** Use full fingerprints for all key identification. RFC 9580
removes short key IDs from the specification entirely. The `openpgp_v6` layer
uses full 32-byte SHA3-256 fingerprints; key IDs in this implementation are
always 8 bytes (first 8 bytes of the fingerprint) and are used only internally,
never as a user-facing identifier.

**Fixed in.** v6 layer (long fingerprints, no short IDs).

---

## 5. SKS Keyserver Certificate Flooding (2019)

**What it exploits.** The SKS (Synchronizing Key Server) network stored OpenPGP
certificates and synchronized them peer-to-peer. Certificates were append-only:
anyone could add signatures to any key, and there was no way to delete them.
The SKS merge protocol imported all signatures without validation.

An attacker uploaded 150,000 fake signatures to the certificates of two
well-known developers (Robert J. Hansen and Daniel Kahn Gillmor, who were aware
of and documented the attack). GPG attempted to import and verify all of these
signatures, consuming minutes of CPU per certificate and eventually running out
of memory. GPG installations that automatically refreshed keys from keyservers
became unusable.

A separate variant uploaded malformed certificates that caused GPG 2.2 to crash
on import.

**Why PGP was affected.** The web of trust model requires publicly writable
key storage. Certificates are designed to accumulate third-party signatures as
trust evidence. There was no rate limiting, no signature count limit, and no
mechanism for a key owner to reject signatures.

**Mitigation.** Keys for Better Email (keys.openpgp.org) is a keyserver that
verifies email ownership before publishing keys and requires explicit opt-in for
third-party signatures. It does not federate with SKS. Web Key Directory (WKD)
publishes keys via HTTPS at a well-known URL under the key owner's domain,
removing the append-only public keyserver entirely.

This implementation does not include key management. The attack applies at the
key distribution layer, not at the cryptographic layer covered here.

**Fixed in.** Not fixed in any cryptographic layer. Requires changing the key
distribution model.

---

## 6. EFAIL -- Unauthenticated Encryption and HTML Exfiltration (2018)

**What it exploits.** EFAIL is a class of attacks, not a single attack. The two
main variants:

Direct exfiltration: some email clients decrypted PGP messages and then loaded
remote images referenced in the plaintext HTML. An attacker who could modify the
ciphertext in transit (or who stored the ciphertext) could wrap it in an HTML
image tag such that, when decrypted, the plaintext was appended to a URL that
the email client would fetch. The attacker controls the server at that URL and
receives the plaintext.

CBC/CFB gadget attack: even with MDC enabled, certain implementations did not
abort on MDC failure immediately. Instead they returned the partially decrypted
plaintext before checking the MDC. By manipulating specific bytes in the SED or
SEIPD v1 ciphertext, an attacker could inject an HTML image tag prefix into the
decrypted output, causing the same exfiltration.

**Why PGP was affected.**

1. SEIPD v1's MDC is not real authenticated encryption. It is a SHA-1 hash
   appended to the plaintext before CFB encryption. The MDC does not prevent
   partial decryption output from being returned before verification.

2. Email clients treated decrypted HTML as trusted content, including loading
   remote resources.

3. Some implementations silently fell back to the unauthenticated SED (tag 9)
   packet when SEIPD was not supported, bypassing the MDC entirely.

**Mitigation.**

SEIPD v2 (RFC 9580) uses AEAD encryption. Under AEAD, any ciphertext
modification causes decryption to fail before any plaintext is returned. There
is no partial output and no MDC timing window.

Email client fixes: HTML rendering should not load remote resources from
decrypted content. This is an application-layer fix independent of the
cryptographic layer.

**Fixed in.** v6 layer (SEIPD v2 mandatory AEAD).

---

## 7. Harvest Now, Decrypt Later (Ongoing)

**What it exploits.** An adversary records encrypted traffic or stored
ciphertext today. When a cryptographically relevant quantum computer becomes
available, they use Shor's algorithm to break the RSA or ECDH key exchange and
recover the session key, then decrypt the stored ciphertext.

The timeline for cryptographically relevant quantum computers is contested.
NIST's post-quantum standardization effort was motivated by the consensus that
the threat is plausible within 15-30 years. For data that must remain
confidential for decades -- government secrets, medical records, long-term
business data -- this is a real planning horizon.

**Why PGP is affected.** PGP long-lived keys mean the same RSA or EC key pair
may be used for years or decades. Every message encrypted to that key is
retroactively vulnerable once the key is broken. There is no forward secrecy:
breaking the private key breaks all past messages.

**Mitigation.** The `pq_hybrid` layer uses ML-KEM-768 (FIPS 203) combined with
X25519 in a hybrid construction. The combined shared secret requires breaking
both algorithms. ML-KEM is based on the hardness of the Module Learning With
Errors (MLWE) problem, for which no efficient quantum algorithm is known.

NIST selected ML-KEM as FIPS 203 in August 2024. Cloudflare deployed
X25519+Kyber768 in TLS 1.3 in 2023. Chrome enabled it by default in 2024.

**Fixed in.** pq_hybrid layer.

---

## 8. Metadata Leakage (Structural, Unfixed)

**What it exploits.** OpenPGP encryption protects message content but not
metadata. In a standard PGP-encrypted email:

- The From, To, CC, and Subject headers are plaintext.
- The key IDs of the intended recipients are embedded in the PKESK packets in
  plaintext. An observer who has collected public keys (from keyservers) can
  determine who the message was intended for.
- The time the message was sent is in the email headers.
- The size of the encrypted payload reveals rough information about content length.

The key ID leak is sometimes called the "PKESK key ID oracle." It allows passive
surveillance of who is communicating with whom, even without breaking encryption.

**Mitigations attempted.**

RFC 4880 allows a PKESK with key ID `0000000000000000` (all zeros), which hides
the recipient. The decryptor must try all available private keys. This trades
anonymity for decryption cost and is rarely implemented in practice.

The `age` format does not transmit key IDs at all. The recipient tries each
available identity against each stanza until one decrypts successfully. This is
the correct design but requires trying all identities, which is computationally
feasible because ChaCha20-Poly1305 is fast.

**Fixed in.** age_like and pq_hybrid layers (no key IDs transmitted). Not fixed
in classic, v4, or v6 layers (key IDs are in the PKESK).

---

## Summary Table

| Attack | Year | Root Cause | Fixed In |
|---|---|---|---|
| Bleichenbacher PKCS#1 v1.5 oracle | 1998 | Padding oracle in RSA | v4 (ECDH replaces RSA) |
| Mister-Zuccherato CFB oracle | 2005 | No symmetric integrity | v4 (SEIPD v1 MDC) |
| SHA-1 collision | 2004-2017 | Weak hash in fingerprints | v6 (SHA3-256) |
| Short key ID spoofing | 2014 | 32/64-bit key IDs | v6 (full fingerprints only) |
| SKS keyserver flooding | 2019 | Append-only public key store | Key distribution layer only |
| EFAIL | 2018 | Partial decryption output | v6 (SEIPD v2 AEAD) |
| Harvest now, decrypt later | Ongoing | No post-quantum key exchange | pq_hybrid |
| Metadata / key ID leakage | Structural | Key IDs in plaintext headers | age_like, pq_hybrid |
