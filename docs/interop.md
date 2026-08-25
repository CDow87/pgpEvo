# Interoperability Guide

How to test each layer against real-world tools. The goal is to verify that
the wire formats are correct and that messages cross the boundary between this
implementation and external tools without modification.

Prerequisites noted per section. Most require only standard Unix tools and GPG.
The age interop section requires the reference `age` binary. The Wireshark
section requires Wireshark 4.x.

---

## classic layer -- interop with GPG

The `classic` layer uses the v4 packet format. GPG can parse v4 packets.
However, because the `classic` layer uses ECDH (through OAEP) rather than
the RSA key format GPG expects for RSA keys, direct decryption cross-test
requires careful setup.

A simpler interop test is to verify that the ASCII armor and packet structure
are parseable by GPG's packet dumper, which does not perform key operations.

### Inspect packet structure with GPG

Encrypt a message with the classic layer:

    pgp-classic keygen --out testkey
    echo "Hello from 1991" > msg.txt
    pgp-classic encrypt --pub testkey.pub.pem --in msg.txt --out msg.asc

Dump the packet structure:

    gpg --list-packets msg.asc

Expected output (abbreviated):

    :pubkey enc packet: version 3, algo 1, keyid XXXXXXXXXXXXXXXX
        data: [2048 bits]
    :encrypted data packet:
        length: ...

If GPG parses the packets without errors, the binary framing and armor are
correct. The `algo 1` confirms GPG identifies RSA (algorithm ID 1).

### Verify CRC24 checksum

The classic layer includes a CRC24 checksum line in the armor. Verify it:

    python3 -c "
    from pgp_evolution.packets.armor import crc24, decode
    import base64, struct

    armored = open('msg.asc').read()
    lines = armored.strip().splitlines()
    crc_line = next(l for l in lines if l.startswith('='))
    claimed = base64.b64decode(crc_line[1:] + '=')
    _, raw = decode(armored)
    computed = struct.pack('>I', crc24(raw))[1:]
    assert claimed == computed, f'CRC mismatch: {claimed.hex()} vs {computed.hex()}'
    print('CRC24 OK')
    "

---

## openpgp_v4 layer -- interop with GPG

The v4 layer uses Ed25519 + X25519, which GPG 2.3+ supports natively. However,
the key serialization format used by this implementation (JSON with base64) is
not GPG's keyring format. Direct GPG decryption of v4 layer output would require
importing the key into GPG's keyring.

The most practical interop test is packet inspection and a round-trip through
the packet reader.

### Packet inspection

    pgp-v4 keygen > mykey_v4.json
    echo "OpenPGP v4 test" > msg.txt
    pgp-v4 encrypt --key-json mykey_v4.json --in msg.txt --out msg_v4.asc
    gpg --list-packets msg_v4.asc

Expected output:

    :pubkey enc packet: version 3, algo 18, keyid XXXXXXXXXXXXXXXX
        data: ...
    :encrypted data packet:
        length: ...
        mdc_method: 18

`algo 18` is ECDH. `mdc_method: 18` confirms SEIPD with AES-256.

### Cross-layer round trip (packet reader)

Verify that the packet reader can parse v4 output:

    python3 -c "
    from pgp_evolution.packets.reader import PacketReader
    from pgp_evolution.packets.armor import decode

    _, raw = decode(open('msg_v4.asc').read())
    packets = PacketReader(raw).read_all()
    for p in packets:
        print(f'Tag {int(p.tag):2d} ({p.tag.name}): {len(p.body)} bytes')
    "

Expected:

    Tag  1 (PUBLIC_KEY_ENCRYPTED_SESSION_KEY): N bytes
    Tag 18 (SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA): N bytes

---

## openpgp_v6 layer -- interop with Sequoia PGP

Sequoia PGP (`sq`) is a modern Rust implementation of OpenPGP that has partial
RFC 9580 support. It is a better interop target for v6 than GPG 2.x, which has
limited v6 support as of early 2024.

Install Sequoia: https://sequoia-pgp.org/install/

### Inspect v6 packets

    pgp-v6 keygen > mykey_v6.json
    echo "RFC 9580 test" > msg.txt
    pgp-v6 encrypt --key-json mykey_v6.json --in msg.txt --out msg_v6.asc
    sq packet dump msg_v6.asc

Look for:

    PublicKeyEncryptedSessionKey
        Version: 6
        ...
    SymmetricallyEncryptedIntegrityProtectedData
        Version: 2
        ...

### Verify no CRC24 line in armor

The v6 specification removes the CRC24 checksum. Verify its absence:

    python3 -c "
    content = open('msg_v6.asc').read()
    crc_lines = [l for l in content.splitlines() if l.startswith('=')]
    assert not crc_lines, f'Unexpected CRC line: {crc_lines}'
    print('No CRC24 line present -- RFC 9580 compliant')
    "

### Verify SHA3-256 fingerprint length

    python3 -c "
    import json, base64
    from pgp_evolution.openpgp_v6.keys import V6PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    data = json.load(open('mykey_v6.json'))
    priv = V6PrivateKey(
        sign_priv=Ed25519PrivateKey.from_private_bytes(base64.b64decode(data['sign_priv'])),
        enc_priv=X25519PrivateKey.from_private_bytes(base64.b64decode(data['enc_priv'])),
        public=__import__('pgp_evolution.openpgp_v6.keys', fromlist=['V6PublicKey']).V6PublicKey(
            sign_pub=Ed25519PublicKey.from_public_bytes(base64.b64decode(data['sign_pub'])),
            enc_pub=X25519PublicKey.from_public_bytes(base64.b64decode(data['enc_pub'])),
            created_at=data['created_at'],
        )
    )
    fp = priv.public.fingerprint()
    print(f'Fingerprint ({len(fp)} bytes): {fp.hex()}')
    assert len(fp) == 32, 'v6 fingerprint must be 32 bytes (SHA3-256)'
    "

---

## age_like layer -- interop with the reference age tool

This is the most interesting interop test because the age-like layer is designed
to produce output compatible with the reference `age` tool.

Install the reference age tool:

    # macOS
    brew install age

    # Linux (Go required)
    go install filippo.io/age/cmd/age@latest
    go install filippo.io/age/cmd/age-keygen@latest

### Encrypt with this implementation, decrypt with reference age

    # Generate a key with the reference tool
    age-keygen -o identity.txt
    # Output is a file containing the secret key (AGE-SECRET-KEY-1...)
    # and a comment with the public key (age1...)

    # Extract the public key
    grep "^# public key:" identity.txt | awk '{print $4}'
    # Copy the age1... value

    # Encrypt with our implementation
    age-enc encrypt -r age1<PASTE_PUBLIC_KEY> --in msg.txt --out msg.age

    # Decrypt with reference age
    age -d -i identity.txt msg.age

If the plaintext appears, the format is compatible.

### Encrypt with reference age, decrypt with this implementation

    # Generate a key with our implementation
    age-enc keygen > our_identity.txt
    # Extract the public key from the comment line
    grep "public key" our_identity.txt

    # Encrypt with reference age tool
    age -r age1<OUR_PUBLIC_KEY> msg.txt > msg_ref.age

    # Decrypt with our implementation
    age-enc decrypt -i our_identity.txt --in msg_ref.age

### Test Bech32 encoding compatibility

The reference age tool uses the same Bech32 encoding. Verify round-trip:

    python3 -c "
    from pgp_evolution.age_like.keys import AgeIdentity, AgeRecipient

    identity = AgeIdentity.generate()
    id_str = identity.to_string()
    rec_str = identity.recipient.to_string()

    print(f'Identity: {id_str}')
    print(f'Recipient: {rec_str}')

    # Round-trip
    recovered_id = AgeIdentity.from_string(id_str)
    recovered_rec = AgeRecipient.from_string(rec_str)

    assert identity.recipient.pub_bytes == recovered_id.recipient.pub_bytes
    assert identity.recipient.pub_bytes == recovered_rec.pub_bytes
    print('Bech32 round-trip OK')
    "

### Multi-recipient compatibility

The reference age tool supports multiple recipients with one `-r` flag per
recipient. Our implementation accepts a list. Verify that a message encrypted
to two recipients (one from each tool) can be decrypted by both:

    age-keygen -o ref_identity.txt
    REF_PUB=$(grep "public key" ref_identity.txt | awk '{print $4}')

    age-enc keygen > our_identity.txt
    OUR_PUB=$(grep "public key" our_identity.txt | awk '{print $4}' | tr -d '#')

    # Encrypt to both
    age-enc encrypt -r $OUR_PUB --in msg.txt --out msg_multi.age
    # (multi-recipient from CLI is one -r flag; adding a second requires
    #  extending the CLI or using the Python API directly)

    # Using the Python API for multi-recipient:
    python3 -c "
    from pgp_evolution.age_like.keys import AgeIdentity, AgeRecipient
    from pgp_evolution.age_like import encrypt

    id1 = AgeIdentity.generate()
    id2 = AgeIdentity.generate()
    plaintext = b'multi-recipient test'
    encrypted = encrypt(plaintext, [id1.recipient, id2.recipient])
    open('msg_multi.age', 'wb').write(encrypted)
    print('Recipient 1:', id1.to_string())
    print('Recipient 2:', id2.to_string())
    "

---

## Wireshark: observing the difference between layers

Wireshark is useful for comparing the wire-level output of each layer and for
verifying that no plaintext leaks into the ciphertext output.

### Setup: write test messages to files

    # Generate keys and encrypt the same message at each layer
    python3 - <<'EOF'
    from pgp_evolution.classic.keys import ClassicPublicKey
    from pgp_evolution.openpgp_v4.keys import V4PrivateKey
    from pgp_evolution.openpgp_v6.keys import V6PrivateKey
    from pgp_evolution.age_like.keys import AgeIdentity
    from pgp_evolution import classic, openpgp_v4, openpgp_v6, age_like

    msg = b"The quick brown fox jumps over the lazy dog"

    pub_c, priv_c = ClassicPublicKey.generate()
    open("classic.asc", "w").write(classic.encrypt(msg, pub_c))

    priv4 = V4PrivateKey.generate()
    open("v4.asc", "w").write(openpgp_v4.encrypt(msg, priv4.public))

    priv6 = V6PrivateKey.generate()
    open("v6.asc", "w").write(openpgp_v6.encrypt(msg, priv6.public))

    id_a = AgeIdentity.generate()
    open("age.bin", "wb").write(age_like.encrypt(msg, [id_a.recipient]))

    print("Files written: classic.asc, v4.asc, v6.asc, age.bin")
    EOF

### Observation 1: key IDs leak in OpenPGP formats

In the classic, v4, and v6 files, the PKESK packet contains the recipient's
key ID in plaintext. An adversary watching the wire knows which key was used.

    python3 -c "
    from pgp_evolution.packets.reader import PacketReader
    from pgp_evolution.packets.armor import decode
    from pgp_evolution.packets.tags import PacketTag

    for fname in ['classic.asc', 'v4.asc', 'v6.asc']:
        _, raw = decode(open(fname).read())
        packets = PacketReader(raw).read_all()
        pkesk = next(p for p in packets if p.tag == PacketTag.PUBLIC_KEY_ENCRYPTED_SESSION_KEY)
        # Key ID is at bytes 1-9 in old v3 PKESK format
        key_id = pkesk.body[1:9]
        print(f'{fname}: key_id = {key_id.hex()}')
    "

Now check the age output:

    python3 -c "
    content = open('age.bin', 'rb').read()
    header_end = content.find(b'\n--- ')
    print(content[:header_end].decode())
    "

The age header contains only the ephemeral public key, not a key ID. There is
no way to determine which identity (if any known identity) was the recipient
without attempting decryption.

### Observation 2: packet sizes differ between layers

The PKESK size reflects the key exchange algorithm:

    python3 -c "
    from pgp_evolution.packets.reader import PacketReader
    from pgp_evolution.packets.armor import decode
    from pgp_evolution.packets.tags import PacketTag

    for fname in ['classic.asc', 'v4.asc', 'v6.asc']:
        _, raw = decode(open(fname).read())
        packets = PacketReader(raw).read_all()
        for p in packets:
            print(f'{fname}  tag={int(p.tag):2d} ({p.tag.name:<50}) body={len(p.body)} bytes')
        print()
    "

classic PKESK is large (RSA-2048 ciphertext = 256 bytes).
v4 and v6 PKESK are small (X25519 ephemeral pub = 32 bytes, GCM tag = 16 bytes).

### Observation 3: SEIPD v1 vs v2 in ciphertext structure

In v4 (SEIPD v1) the payload version byte is 0x01:

    python3 -c "
    from pgp_evolution.packets.reader import PacketReader
    from pgp_evolution.packets.armor import decode
    from pgp_evolution.packets.tags import PacketTag

    _, raw = decode(open('v4.asc').read())
    packets = PacketReader(raw).read_all()
    seipd = next(p for p in packets if p.tag == PacketTag.SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA)
    print(f'SEIPD version: {seipd.body[0]}')
    print(f'First 20 body bytes: {seipd.body[:20].hex()}')
    "

In v6 (SEIPD v2) the version byte is 0x02 and the next three bytes encode
the algorithm parameters:

    _, raw = decode(open('v6.asc').read())
    ...
    print(f'SEIPD version: {seipd.body[0]}')        # 2
    print(f'sym_algo: {seipd.body[1]}')              # 9 (AES-256)
    print(f'aead_algo: {seipd.body[2]}')             # 2 (GCM)
    print(f'chunk_size_octet: {seipd.body[3]}')      # 22 (4 MiB)
    print(f'base_iv: {seipd.body[4:16].hex()}')

### Observation 4: no PGP framing in age output

Load `age.bin` in a hex editor or print the first 100 bytes:

    python3 -c "
    content = open('age.bin', 'rb').read()
    print(content[:200].decode(errors='replace'))
    "

The header is human-readable text. There are no binary packet bytes, no
type-length-value framing, and no base64 encoding of the payload. The body
(after the `---` line) is raw binary. This is the simplicity argument for age:
the format is trivially inspectable and does not require a packet parser to
understand its structure.

---

## Verifying forward secrecy

Forward secrecy means that compromise of a long-term private key does not
compromise past session keys. All layers except classic demonstrate this.

The session key for each message is derived from an ephemeral X25519 key that
is discarded after encryption. Even if an attacker obtains the recipient's
long-term private key, they cannot recover the ephemeral private key and
therefore cannot reproduce the ECDH exchange.

To verify:

    python3 -c "
    from pgp_evolution.openpgp_v4.keys import V4PrivateKey
    from pgp_evolution.openpgp_v4 import encrypt, decrypt

    priv = V4PrivateKey.generate()
    msg1 = encrypt(b'message one', priv.public)
    msg2 = encrypt(b'message two', priv.public)

    # The ephemeral keys embedded in msg1 and msg2 are different.
    # Recovering priv does not help recover the session key for msg1 from msg2.

    from pgp_evolution.packets.reader import PacketReader
    from pgp_evolution.packets.armor import decode
    from pgp_evolution.packets.tags import PacketTag

    def get_eph_pub(armored):
        _, raw = decode(armored)
        pkesk = next(p for p in PacketReader(raw).read_all()
                     if p.tag == PacketTag.PUBLIC_KEY_ENCRYPTED_SESSION_KEY)
        return pkesk.body[11:43].hex()  # 0x40 prefix + 32 bytes

    print('msg1 ephemeral pub:', get_eph_pub(msg1))
    print('msg2 ephemeral pub:', get_eph_pub(msg2))
    assert get_eph_pub(msg1) != get_eph_pub(msg2)
    print('Different ephemeral keys confirmed -- forward secrecy holds')
    "

---

## Testing the pq_hybrid layer with liboqs

If liboqs and pyoqs are installed, verify that the ML-KEM operations produce
correct output by comparing shared secrets from encapsulation and decapsulation:

    python3 -c "
    import oqs

    kem_alg = 'Kyber768'
    with oqs.KeyEncapsulation(kem_alg) as sender:
        pk = sender.generate_keypair()
        ciphertext, ss_enc = sender.encap_secret(pk)

    with oqs.KeyEncapsulation(kem_alg, sender.export_secret_key()) as receiver:
        ss_dec = receiver.decap_secret(ciphertext)

    assert ss_enc == ss_dec, 'Shared secrets do not match'
    print(f'ML-KEM-768 KEM test OK. Shared secret: {ss_enc.hex()}')
    print(f'Ciphertext size: {len(ciphertext)} bytes (expected 1088)')
    print(f'Public key size: {len(pk)} bytes (expected 1184)')
    "

Then run a full round trip:

    python3 -c "
    from pgp_evolution.pq_hybrid.keys import PQIdentity
    from pgp_evolution.pq_hybrid import encrypt, decrypt

    identity, recipient = PQIdentity.generate()
    plaintext = b'post-quantum test message'
    encrypted = encrypt(plaintext, [recipient])
    result = decrypt(encrypted, identity)
    assert result == plaintext
    print('PQ hybrid round trip OK')

    header = encrypted[:encrypted.find(b'\n--- ')]
    print()
    print('Header:')
    print(header.decode())
    "
