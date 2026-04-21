# Secure Chat Project

- mutual authentication
- message secrecy
- message integrity
- perfect forward secrecy
- basic replay protection
- safer length-checked network parsing

## What it uses

- **Ed25519** for long-term identity signatures
- **X25519** for ephemeral key exchange
- **HKDF-SHA256** to derive per-session keys
- **AES-256-CTR** for encryption
- **HMAC-SHA256** for integrity (encrypt-then-MAC)
- **TCP** sockets for transport

## Security design

Handshake:
1. Client sends nonce + ephemeral X25519 public key + name.
2. Server sends nonce + ephemeral X25519 public key + name + Ed25519 signature over the transcript hash.
3. Client verifies the server signature and replies with its own signature over the transcript hash.
4. Both sides derive fresh symmetric keys from the X25519 shared secret and transcript hash.

Data packets:
- sequence number
- IV
- ciphertext
- HMAC over header + ciphertext

Replay protection:
- each side tracks the largest sequence number received
- packets with old or repeated sequence numbers are rejected

## Build

```bash
make
```

Dependencies:
- OpenSSL headers and libraries
- a C compiler

Example on Debian/Ubuntu:

```bash
sudo apt-get install build-essential libssl-dev
```

Example on macOS with Homebrew:

```bash
brew install openssl
```

## Generate identity keys

Create one keypair for each user.

```bash
openssl genpkey -algorithm ED25519 -out alice_priv.pem
openssl pkey -in alice_priv.pem -pubout -out alice_pub.pem

openssl genpkey -algorithm ED25519 -out bob_priv.pem
openssl pkey -in bob_priv.pem -pubout -out bob_pub.pem
```

## Run

Terminal chat:

Server:

```bash
./secure_chat -l 5555 -k alice_priv.pem -p bob_pub.pem -n Alice
```

Client:

```bash
./secure_chat -c 127.0.0.1 5555 -k bob_priv.pem -p alice_pub.pem -n Bob
```
