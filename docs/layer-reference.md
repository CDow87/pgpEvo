# Layer Reference

Technical reference for each layer's wire format, key derivation, and packet
structure. Read this alongside the source code.

---

## Shared: OpenPGP Packet Format

Layers `classic`, `openpgp_v4`, and `openpgp_v6` all use the OpenPGP binary
packet format defined in RFC 4880 and RFC 9580. The `age_like` and `pq_hybrid`
layers use a text-based stanza format instead.

### Packet header

Every OpenPGP packet begins with a header byte where bit 7 is always 1.

Old format (bit 6 = 0):

    bit 7: always 1
    bit 6: 0 (old format)
    bits 5-2: packet tag (4 bits, 0-15)
    bits 1-0: length type
      00 = 1-byte length follows
      01 = 2-byte length follows
      10 = 4-byte length follows
      11 = indeterminate (read until EOF)

New format (bit 6 = 1):

    bit 7: always 1
    bit 6: 1 (new format)
    bits 5-0: packet tag (6 bits, 0-63)

New-format length encoding (the byte after the header):

    0-191:    literal length
    192-223:  two-byte length: ((first - 192) << 8) + second + 192
    224-254:  partial body: chunk size is 2^(first & 0x1F), more chunks follow
    255:      four-byte length follows (big-endian uint32)

RFC 9580 requires new-format headers exclusively. Old-format headers appear in
practice only when parsing legacy GPG output.

Source: [pgp_evolution/packets/reader.py](../pgp_evolution/packets/reader.py)

---

## Layer 1: classic

### Algorithm profile

| Role | Algorithm | Notes |
|---|---|---|
| Public-key encryption | RSA-2048-OAEP-SHA256 | Original used PKCS#1 v1.5, which is vulnerable |
| Symmetric encryption | AES-128-CFB | Original used IDEA; same structural weakness |
| Integrity | None | Deliberate -- demonstrates the weakness |
| Hash | SHA-1 (fingerprint only) | Broken for collision resistance |

### Key fingerprint (v4 format)

    SHA-1(0x99 || uint16be(body_len) || public_key_body)

Where `public_key_body` is:

    version(1) = 0x04
    created_at(4) big-endian unix timestamp
    algorithm(1) = 0x01 (RSA)
    MPI(n)       RSA modulus
    MPI(e)       RSA public exponent

MPI encoding: `uint16be(bit_length) || big_endian_bytes(value)`

### Key ID

Low 64 bits (last 8 bytes) of the fingerprint.

### Encryption packet sequence

    [Tag 1] Public-Key Encrypted Session Key (PKESK)
    [Tag 9] Symmetrically Encrypted Data (SED)

PKESK body:

    version(1) = 0x03
    key_id(8)
    algorithm(1) = 0x01 (RSA)
    MPI(encrypted_session_key)

SED body (no integrity protection):

    IV(16) || AES-128-CFB(session_key, plaintext)

The absence of a MAC means an attacker who can observe decryption behavior can
recover the plaintext one byte at a time. This is the Mister-Zuccherato attack
(2005). The SEIPD packet (tag 18) was introduced specifically to close this.

### ASCII armor

    -----BEGIN PGP MESSAGE-----

    <base64, 76 chars per line>
    =<base64(CRC24)>
    -----END PGP MESSAGE-----

CRC24 parameters: init = 0xB704CE, poly = 0x1864CFB.

---

## Layer 2: openpgp_v4

### Algorithm profile

| Role | Algorithm | Notes |
|---|---|---|
| Signing | Ed25519 | Primary key |
| Key agreement | X25519 ECDH | Encryption subkey |
| KDF | HKDF-SHA256 | Derives per-message wrapping key |
| Session key wrap | AES-256-GCM | Wraps the 256-bit file key |
| Symmetric encryption | AES-256-GCM | Encrypts the payload |
| Integrity | SEIPD v1 + SHA-1 MDC | Weaker than AEAD; see attack catalog |

### Key fingerprint (v4 format)

Same structure as classic but with EdDSA algorithm byte and OID:

    SHA-1(0x99 || uint16be(body_len) || public_key_body)

    public_key_body:
      version(1) = 0x04
      created_at(4)
      algorithm(1) = 0x16 (EdDSA = 22)
      OID length(1) = 0x09
      OID(9) = 2B 06 01 04 01 DA 47 0F 01  (Ed25519)
      0x40 || ed25519_public_key(32)

The `0x40` prefix indicates a native (uncompressed, non-SEC1) elliptic curve
point. It is defined in the ECDH/EdDSA extensions to RFC 4880.

### Key ID

Last 8 bytes of the v4 fingerprint. This is the design that enabled the "Evil32"
attack -- 64 bits is short enough for birthday collisions to be practical with
a few GPU-months of work.

### ECDH key agreement (X25519)

    ephemeral_priv = random X25519 key
    shared_secret = X25519(ephemeral_priv, recipient_pub)
    wrapping_key = HKDF-SHA256(
        ikm  = shared_secret,
        salt = none,
        info = "OpenPGP_ECDH" || recipient_fingerprint,
        len  = 32
    )
    encrypted_session_key = AES-256-GCM(wrapping_key, nonce, session_key)

The ephemeral public key is transmitted in the PKESK packet so the recipient
can reproduce the ECDH exchange.

### Encryption packet sequence

    [Tag 1]  Public-Key Encrypted Session Key (PKESK)
    [Tag 18] Symmetrically Encrypted Integrity Protected Data (SEIPD v1)

PKESK body:

    version(1) = 0x03
    key_id(8)
    algorithm(1) = 0x12 (ECDH = 18)
    0x40 || ephemeral_x25519_pub(32)
    nonce(12)
    encrypted_session_key(32 + 16 tag)

SEIPD v1 body:

    version(1) = 0x01
    data_nonce(12)
    AES-256-GCM(session_key, data_nonce, plaintext || mdc_suffix)

MDC suffix: `0xD3 0x14 || SHA-1(plaintext || 0xD3 0x14)`

### ASCII armor

Same as classic, including CRC24 checksum. RFC 4880 makes the checksum
mandatory; RFC 9580 makes it optional and recommends omitting it.

---

## Layer 3: openpgp_v6

### Changes from v4

- Version byte is 6 in all packets (PKESK, SEIPD)
- Fingerprint uses SHA3-256 instead of SHA-1 (32 bytes, not 20)
- Key ID is the FIRST 8 bytes of the fingerprint (v4 used the last 8)
- SEIPD version 2 with chunk-based mandatory AEAD
- No CRC24 checksum in ASCII armor
- MD5 and SHA-1 removed from the algorithm registry

### Key fingerprint (v6 format)

    SHA3-256(0x9B || uint32be(body_len) || public_key_body)

Note the prefix byte changes from `0x99` (v4) to `0x9B` (v6) and the length
field grows from 2 to 4 bytes. This makes v4 and v6 fingerprints impossible to
confuse.

### SEIPD v2 structure

SEIPD v2 body:

    version(1) = 0x02
    sym_algo(1) = 0x09 (AES-256)
    aead_algo(1) = 0x02 (GCM; 0x01 = OCB, 0x03 = EAX)
    chunk_size_octet(1) = 22  (means 2^22 = 4 MiB chunks)
    base_iv(12)
    encrypted_chunk_0
    encrypted_chunk_1
    ...
    final_auth_tag  (AES-GCM of empty plaintext, authenticates chunk count)

Each chunk nonce is derived by XOR-ing the base IV with the chunk index
(big-endian, 12 bytes). This makes nonces unique per chunk and per message.

Associated data for each chunk:

    packet_header_byte(1)  = 0xC0 | tag
    version(1)             = 2
    sym_algo(1)
    aead_algo(1)
    chunk_size_octet(1)
    chunk_index(8)         big-endian uint64

The final authentication tag uses `chunk_count` as its index. This prevents
truncation attacks: removing the last chunk changes the count and invalidates
the final tag.

### Note on AES-OCB

RFC 9580's preferred AEAD mode is AES-256-OCB (algo ID 1). OCB is faster than
GCM on hardware without AES-GCM acceleration because it requires only one AES
pass per block instead of two. Python's `cryptography` library does not expose
OCB through its high-level API. The implementation uses AES-256-GCM (algo ID 2)
as a structural equivalent. A production implementation would use cffi bindings
to `EVP_EncryptInit_ex` with `EVP_aes_256_ocb()`.

---

## Layer 4: age_like

### Format overview

The age v1 format uses a text header followed by a binary body. The header is
line-oriented ASCII. The body is a raw binary stream.

Header structure:

    age-encryption.org/v1
    -> X25519 <base64url-no-pad(ephemeral_pub)>
    <base64url-no-pad(encrypted_file_key)>
    [additional recipient stanzas ...]
    --- <base64url-no-pad(header_mac)>

Binary body:

    payload_nonce(16) || encrypted_chunks

### Key encoding

Keys are Bech32-encoded per BIP-0173.

    Identity (private): AGE-SECRET-KEY-1<bech32(raw_x25519_priv)>
    Recipient (public): age1<bech32(raw_x25519_pub)>

### File key derivation

For each recipient:

    ephemeral_priv = random X25519 key
    shared_secret = X25519(ephemeral_priv, recipient_pub)
    salt = ephemeral_pub_bytes || recipient_pub_bytes
    enc_key = HKDF-SHA256(
        ikm  = shared_secret,
        salt = salt,
        info = "age-encryption.org/v1/X25519",
        len  = 32
    )
    encrypted_file_key = ChaCha20-Poly1305(enc_key, nonce=0^12, file_key)

The 12-byte all-zero nonce is safe here because `enc_key` is derived from a
fresh ephemeral key and is never reused.

### Header MAC

    mac_key = HKDF-SHA256(file_key, salt=b"", info="header", len=32)
    header_mac = HMAC-SHA256(mac_key, header_bytes_up_to_dashes)

This authenticates the full header so recipients detect any modification to
recipient stanzas before attempting decryption.

### Payload encryption

    body_key = HKDF-SHA256(file_key, salt=payload_nonce, info="payload", len=32)

Chunks of 65536 bytes (64 KiB) each encrypted with ChaCha20-Poly1305.

Nonce for chunk N:

    N.to_bytes(11, 'big') || (0x01 if last_chunk else 0x00)

The last-chunk flag makes truncation detectable: if an attacker removes the
final chunk, the second-to-last chunk's tag (which was computed with flag=0)
will no longer verify when the decryptor treats it as the last chunk (flag=1).

---

## Layer 5: pq_hybrid

### Stanza type

    -> X25519+MLKEM768 <base64(eph_x25519_pub)> <base64(mlkem_ciphertext)>
    <base64(encrypted_file_key)>

### Recipient key structure

A recipient has two public keys:

    x25519_pub(32)    classical key agreement
    mlkem_pub(1184)   ML-KEM-768 public key (FIPS 203)

### Hybrid shared secret

    ss_classical = X25519(ephemeral_x25519_priv, recipient_x25519_pub)
    (mlkem_ciphertext, ss_pq) = ML-KEM-768.Encaps(recipient_mlkem_pub)

    combined_ikm = ss_classical || ss_pq

    salt = eph_x25519_pub || recipient_x25519_pub || mlkem_ciphertext

    enc_key = HKDF-SHA256(
        ikm  = combined_ikm,
        salt = salt,
        info = "pq-age/v1/X25519+MLKEM768",
        len  = 32
    )

    encrypted_file_key = ChaCha20-Poly1305(enc_key, nonce=0^12, file_key)

The salt includes the ML-KEM ciphertext so the enc_key is bound to the specific
encapsulation. An attacker cannot substitute a different ciphertext without
changing the salt, which changes enc_key, which fails decryption.

### ML-KEM-768 sizes (FIPS 203)

| Value | Size |
|---|---|
| Public key | 1184 bytes |
| Secret key | 2400 bytes |
| Ciphertext | 1088 bytes |
| Shared secret | 32 bytes |

### Security argument

To recover `combined_ikm` an attacker must recover both `ss_classical` and
`ss_pq`. Recovering `ss_classical` requires breaking X25519 (requires a quantum
computer with thousands of logical qubits). Recovering `ss_pq` requires breaking
ML-KEM-768 (requires an algorithm attack on module lattices, for which none is
known as of 2024). The combined security is therefore:

    min(classical_security, pq_security)

where both terms are currently considered strong. If either algorithm is later
broken individually, the other still protects the session.

### Body encryption

Identical to the age_like layer: ChaCha20-Poly1305, 64 KiB chunks, same nonce
construction and truncation protection.
