python3 shellcrypt.py -i sc.bin -m aes -k 0123456789abcdef0123456789abcdef --encode base64 -f c

python3 shellcrypt.py -i sc.bin -m rc4 -k 's3cr3t' --stub rc4 -o pic.bin --verify --meta loader.json

python3 shellcrypt.py -i sc.bin -m uuid -f txt


Ciphers: -m aes (CBC/CTR, 16/24/32B key), xor (rolling multi-byte key, 1–255B), uuid (GUID-format UUID string list for UuidFromStringA-style loaders), rc4, bcrypt (used as a passphrase KDF — one-way hash stretched via SHA-256 into an XOR keystream; the salt/hash are exported so decryption works with the passphrase), chacha20, plus none

Signature shifting: --encode base64|hex|uuid stacks an encoding layer on top of the ciphertext, and -f c | py | txt | asm | bin changes the file/static form

Position-independent output: --stub xor|rc4 assembles a single PIC x86-64 blob — [decryptor][payload][key][keylen] — that decrypts in place and jumps to the payload; RIP-relative only, executable from any base address (nasm or keystone-engine)

Operational niceties: auto-generated keys/IVs/nonces/salts echoed to stdout and saved via --meta loader.json, --verify round-trip check, hex/base64/stdin input, --key-hex, -f asm dumps the stub source
