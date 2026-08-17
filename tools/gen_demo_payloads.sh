#!/usr/bin/env bash
# gen_demo_payloads.sh - regenerate all demo payloads with DETERMINISTIC keys.
# Every artifact is reproducible: the same command line always produces the
# same ciphertext (keys/IV/nonce/salt are fixed below).
set -euo pipefail
cd "$(dirname "$0")/.."          # project root
SC=shellcrypt.py
OUT=payloads

AES_KEY=3031323334353637383961626364656630313233343536373839616263646566
AES_IV=00112233445566778899aabbccddeeff
XOR_KEY=a1b2c3d4e5f60718293a4b5c6d7e8f90
RC4_KEY=deadbeefcafebabefeedfacec0ffee00
CHACHA_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
CHACHA_NONCE=0001020304050607
BCRYPT_PASS='S3cr3tBcryptPass!'
BCRYPT_SALT=0112233445566778899aabbccddeeff0   # encodes to "$2b$10$.PGhLCTUX1gHkos6xb5t6." (builder byte-aligned base64)

for size in 4b 300b; do
  IN=$OUT/demo_$size.bin
  python3 $SC -i "$IN" -m aes --aes-mode cbc --key-hex -k "$AES_KEY" --iv "$AES_IV" \
      --verify -q -f bin -o "$OUT/aes_cbc_${size}.bin" --meta "$OUT/aes_cbc_${size}.meta.json"
  python3 $SC -i "$IN" -m aes --aes-mode ctr --key-hex -k "$AES_KEY" --iv "$AES_IV" \
      --verify -q -f bin -o "$OUT/aes_ctr_${size}.bin" --meta "$OUT/aes_ctr_${size}.meta.json"
  python3 $SC -i "$IN" -m xor --key-hex -k "$XOR_KEY" \
      --verify -q -f bin -o "$OUT/xor_${size}.bin" --meta "$OUT/xor_${size}.meta.json"
  python3 $SC -i "$IN" -m rc4 --key-hex -k "$RC4_KEY" \
      --verify -q -f bin -o "$OUT/rc4_${size}.bin" --meta "$OUT/rc4_${size}.meta.json"
  python3 $SC -i "$IN" -m chacha20 --key-hex -k "$CHACHA_KEY" --nonce "$CHACHA_NONCE" \
      --verify -q -f bin -o "$OUT/chacha20_${size}.bin" --meta "$OUT/chacha20_${size}.meta.json"
  python3 $SC -i "$IN" -m bcrypt -k "$BCRYPT_PASS" --salt "$BCRYPT_SALT" --bcrypt-rounds 10 \
      --verify -q -f bin -o "$OUT/bcrypt_${size}.bin" --meta "$OUT/bcrypt_${size}.meta.json"
  python3 $SC -i "$IN" -m uuid \
      --verify -q -f txt -o "$OUT/uuid_${size}.txt" --meta "$OUT/uuid_${size}.meta.json"
done
echo "[+] all demo payloads regenerated"
