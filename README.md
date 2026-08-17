# shellcrypt2 - Shellcode Obfuscation Toolkit

Encrypts / obfuscates raw shellcode with **AES, XOR, UUID, RC4, bcrypt or
ChaCha20**, applies an optional **signature-shifting encode layer**
(base64 / hex / UUID strings), and can emit **position-independent x86-64
decryptor stubs** (XOR / RC4) that decrypt the payload in place and jump
to it, so the resulting blob runs from any base address.

Ships with **C++ and C# loader templates** for every cipher: each template
embeds the encrypted payload, decrypts it at runtime, and provides a simple
execution method (RWX memory + function pointer). All 28 loader tests pass
(14 C++ on Linux + mingw-w64 Windows compile-check, 14 C# under mono).

---

## Capabilities

| Feature | Details |
|---|---|
| Ciphers | AES-256 (CBC / CTR), XOR (1..255-byte rolling key), UUID string packing, RC4, bcrypt-as-KDF, ChaCha20 |
| Encode layer (`--encode`) | `none`, `base64`, `hex`, `uuid` - applied *after* encryption to change the static signature |
| PIC output (`--stub`) | x86-64 position-independent XOR / RC4 decryptor stub, assembled with nasm or keystone-engine |
| Output formats (`-f`) | `bin`, `txt`, `c`, `cs` (C#), `py`, `asm` (stub assembly source) |
| Key handling | Passphrase strings or raw hex (`--key-hex`); random keys by default; all parameters echoed and saved with `--meta` |
| Verification | `--verify` runs a local encrypt/decrypt round-trip on every artifact |
| Loader templates | C++ (manual crypto, no dependencies) and C# (BCL crypto) for all 6 ciphers, x86-64 |
| Demo payloads | Deterministic 4B (`push 1; pop rax; ret` -> returns 1) and 300B (NOP sled + `mov eax,42; ret` -> returns 42) |

---

## Requirements

- Python 3.8+ with `pycryptodome` for AES / RC4 / ChaCha20:
  `pip install pycryptodome`
- `bcrypt` for the bcrypt method: `pip install bcrypt`
- `nasm` (or `keystone-engine` Python package) for `--stub`
- Optional: `g++` / `mono-devel` (`mcs`) / `mingw-w64` for the loader templates

---

## Usage

```
python3 shellcrypt2.py -i shellcode.bin -m <method> [options]
```

### Options

| Option | Description |
|---|---|
| `-i FILE`, `-x HEX`, `-b B64` | shellcode input (file, hex string, base64 string) |
| `-m, --method` | `aes` \| `xor` \| `uuid` \| `rc4` \| `bcrypt` \| `chacha20` \| `none` (default `xor`) |
| `-k, --key KEY` | key / passphrase (see per-method rules below) |
| `--key-hex` | interpret `--key` as raw hex bytes |
| `--xor-keysize N` | XOR key length when `-k` is omitted (default 16, max 255) |
| `--aes-mode` | `cbc` (default) \| `ctr` |
| `--iv HEX` | AES IV (16 bytes; random if omitted) |
| `--nonce HEX` | ChaCha20 nonce (8 bytes; random if omitted) |
| `--salt HEX` | bcrypt salt (16 bytes; random if omitted) |
| `--bcrypt-rounds N` | bcrypt cost factor (default 10) |
| `--encode` | `none` \| `base64` \| `hex` \| `uuid` (default `none`) |
| `--stub` | `xor` \| `rc4` - emit PIC decryptor blob (`-m xor`/`-m rc4` only) |
| `-f, --format` | `bin` \| `txt` \| `c` \| `cs` \| `py` \| `asm` (default `bin`) |
| `--c-name`, `--cs-name`, `--py-name` | identifier for generated arrays (default `payload`) |
| `-o FILE` | write output to file |
| `--meta FILE.json` | save all loader parameters (keys, IV, nonce, passphrase...) |
| `--verify` | encrypt/decrypt round-trip check |
| `-q, --quiet` | suppress the summary output |

### Examples

```bash
# XOR-encrypt a blob
python3 shellcrypt2.py -i shellcode.bin -m xor -o out.bin

# AES-256-CBC, base64-encoded, as a C array, with saved params + verify
python3 shellcrypt2.py -i shellcode.bin -m aes --encode base64 -f c \
    --meta loader.json --verify -o payload.h

# RC4 with a fixed key, position-independent x86-64 blob (map RWX, jump to 0)
python3 shellcrypt2.py -i shellcode.bin -m rc4 -k 's3cr3t' --stub rc4 -o pic.bin

# ChaCha20 with explicit key/nonce, C# array output
python3 shellcrypt2.py -i shellcode.bin -m chacha20 --key-hex -k \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    --nonce 0001020304050607 -f cs -o payload.cs

# UUID packing (GUID mixed-endian layout for UuidFromStringA-style loaders)
python3 shellcrypt2.py -i shellcode.bin -m uuid -f txt

# bcrypt-derived keystream from a passphrase
python3 shellcrypt2.py -i shellcode.bin -m bcrypt -k 'P@ssphrase!'
```

---

## Encryption methods

| Method | Description |
|---|---|
| `aes` | AES-256 keyed by 16/24/32-byte key (`-k`, default 32 random). **CBC** with PKCS7 padding, or **CTR** with a 128-bit big-endian counter starting from the IV. Requires `pycryptodome`. |
| `xor` | Multi-byte XOR with a 1..255-byte key. Default 16-byte random key; longer keys raise the static-signature bar. |
| `uuid` | Packs the shellcode into UUID strings using the **bytes_le / GUID mixed-endian layout** (`UuidFromStringA`-compatible). 16 bytes per UUID, zero-padded final chunk; the loader truncates to the original length. Note: this method already produces a UUID string signature, so `--encode` is rejected. |
| `rc4` | RC4 stream cipher, 1..256-byte key (default 16 random). |
| `bcrypt` | **bcrypt used as a passphrase KDF**: `bcrypt.hashpw` -> 60-char hash string -> keystream = repeated `SHA256(hash_str + counter_le32)` XOR-ed over the payload. bcrypt itself is one-way; decryption requires the passphrase (and the hash string / salt baked into the loader). |
| `chacha20` | ChaCha20 stream cipher, 32-byte key, 8-byte nonce. |
| `none` | No cipher - passes the shellcode through the encode layer only. |

All key material is echoed to stdout on every run; persist it with `--meta`
so the loader can be parameterized. Every demo artifact in `payloads/` was
generated with `--verify` and reports `"verify": "PASS"` in its meta JSON.

---

## Signature-shifting encode layer (`--encode`)

Applied *after* the cipher so the on-disk artifact is never raw ciphertext:

- `base64` - ASCII base64 string
- `hex` - ASCII hex string
- `uuid` - UUID string list
- `none` - raw bytes

Combine with `-f` to emit directly as source: e.g.
`-m aes --encode base64 -f c` produces a C `char[]` of the base64 string,
which the C/C# loaders decode before decrypting. Note: `--encode` cannot be
combined with `--stub` (a stub blob must be raw bytes), and `-m uuid`
rejects `--encode` (it already encodes).

---

## Position-independent output (`--stub`)

For `-m xor` and `-m rc4`, `--stub` assembles a single self-contained blob:

```
[stub code][encrypted payload][key][keylen]
```

The x86-64 stub is RIP-relative (PIC), decrypts the payload **in place**,
and jumps into it. Load it as:

```c
void *m = mmap(NULL, len, PROT_READ|PROT_WRITE|PROT_EXEC,
               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
memcpy(m, blob, len);
((void(*)())m)();          // jump to offset 0
```

(Windows: `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`.)

- Assembles with `nasm -f bin` or the `keystone-engine` Python package
  (`pip install keystone-engine`).
- `-f asm --stub xor|rc4` prints the assembly source instead of the blob.
- The resulting bytes are fully position-independent: same blob runs at any
  base address on x86-64 Linux, Windows, or BSD (subject to RWX mapping and
  NX policy).

---

## Loader templates (`loaders/`)

For each cipher (`aes`, `xor`, `uuid`, `rc4`, `bcrypt`, `chacha20`) there is
a standalone loader in both languages. The generated `payload_inc.h` /
`payload_inc.cs` embeds the encrypted demo payload; the loader decrypts it,
maps RWX memory, copies the shellcode in, and calls it via a function
pointer, printing `payload returned N`.

| Language | Location | Crypto |
|---|---|---|
| C++ | `loaders/cpp/<cipher>/<cipher>_loader.cpp` | fully manual (embedded AES tables, SHA-256, ChaCha20) - zero dependencies |
| C# | `loaders/csharp/<cipher>/<cipher>_loader.cs` | BCL `Aes.Create()` / `SHA256.Create()`, manual RC4/ChaCha20 |

Key points:

- **AES** has two variants: CBC+PKCS7 (default) and CTR (`-DAES_MODE=1` for
  C++, `-define:AES_CTR` for C#).
- **bcrypt** loaders embed the bcrypt hash string and stretch it with SHA-256
  exactly as the builder does; they need the passphrase at runtime (or baked
  in as a constant).
- **uuid** loaders parse the UUID strings (`Guid.Parse().ToByteArray()` in
  C#, matching the builder's `bytes_le` layout) and truncate to the original
  length.
- Execution: Linux uses `mmap` RWX; the `_WIN32` / `PlatformID.Win32NT`
  paths use `VirtualAlloc` + `PAGE_EXECUTE_READWRITE`.

### Building & testing the loaders

```bash
# C++ - compiles every cipher with 4B and 300B payloads and asserts
#        the return values (4B -> 1, 300B -> 42). AES runs twice (CBC+CTR).
bash loaders/cpp/build_test.sh          # full suite
bash loaders/cpp/build_test.sh aes      # single cipher

# C# - same matrix, under mono (requires mono-devel)
bash loaders/csharp/build_test.sh
```

Expected output: `[+] all C++ loader tests passed` /
`[+] all C# loader tests passed`.

Windows compile-check (mingw-w64, PE32+ output verified):

```bash
x86_64-w64-mingw32-g++ -O2 -Wall -o loader.exe loaders/cpp/<cipher>/<cipher>_loader.cpp
```

The `mcs`-compiled C# assemblies run on Windows under .NET Framework / mono;
the loader auto-selects `VirtualAlloc` on Windows.

### Embedding your own payload

```bash
# 1. Obfuscate your shellcode, keep the params
python3 shellcrypt2.py -i your_sc.bin -m rc4 -k 'key' --meta meta.json

# 2. Generate the include for a loader template
python3 tools/gen_inc.py rc4 300 --lang cpp --out loaders/cpp/rc4/payload_inc.h
python3 tools/gen_inc.py rc4 300 --lang cs  --out loaders/csharp/rc4/payload_inc.cs

# 3. Build & run the loader (adapt keys/passphrase in the source or meta)
g++ -O2 -Wall -o loader loaders/cpp/rc4/rc4_loader.cpp && ./loader
```

`tools/gen_inc.py` accepts `aes_cbc | aes_ctr | xor | rc4 | bcrypt |
chacha20 | uuid` and sizes `4 | 300` (the sizes shipped in `payloads/`).

---

## Demo payloads (`payloads/`)

Generated by `tools/gen_demo_payloads.sh` from:

- `demo_4b.bin`  = `6a 01 58 c3` (`push 1; pop rax; ret` -> returns 1)
- `demo_300b.bin` = 294x NOP + `b8 2a 00 00 00 c3` (`mov eax,42; ret` -> returns 42)

Artifacts per cipher and size: `<cipher>_<size>b.bin` (raw blob) or
`<cipher>_<size>b.txt` (UUID strings), plus `<cipher>_<size>b.meta.json`
containing `method`, `encode`, `original_len`, `payload_len`, keys, IV,
nonce, passphrase, bcrypt hash, and `"verify": "PASS"`.

All keys are deterministic so loader tests are reproducible (see the meta
JSON for exact values; the xor/rc4/aes/chacha20 keys are documented in the
per-cipher meta files).

---

## Directory layout

```
shellcrypt2/
├── shellcrypt2.py                 # main obfuscation script (CLI)
├── crypto_tables.json            # AES S-box/inv-S-box/Rcon, SHA-256 K/H tables
├── payloads/                     # demo payloads + meta (deterministic keys)
├── tools/
│   ├── gen_demo_payloads.sh      # regenerate all payloads from the demo bins
│   ├── gen_inc.py                # payload_inc.h/.cs generator for loaders
│   └── make_crypto_tables.py     # regenerate crypto_tables.json
└── loaders/
    ├── cpp/                      # C++ templates (manual crypto, dependency-free)
    │   ├── aes/                  #   aes_loader.cpp (+aes_tables.inc, CBC/CTR)
    │   ├── xor/ rc4/ bcrypt/ chacha20/ uuid/
    │   └── build_test.sh         #   compile + execute-test suite
    └── csharp/                   # C# templates (BCL crypto, mono-compatible)
        ├── aes/                  #   aes_loader.cs (CBC default, -define:AES_CTR)
        ├── xor/ rc4/ bcrypt/ chacha20/ uuid/
        └── build_test.sh         #   compile + execute-test suite
```

---

## Test status

- All 6 ciphers verified against the Python builder (`--verify` PASS on
  every demo artifact).
- C++ loaders: 14/14 execute-tests pass (4B -> 1, 300B -> 42, AES CBC+CTR),
  warning-free with `-O2 -Wall`; 7/7 compile clean under mingw-w64 with
  PE32+ output confirmed.
- C# loaders: 14/14 execute-tests pass under mono 6.14; AES CTR via
  `-define:AES_CTR`.

> **Offensive-use note:** this toolkit is intended for authorized security
> assessments, malware research, and EDR/AV signature-evaluation labs.
> Only process shellcode you are explicitly licensed to test.
