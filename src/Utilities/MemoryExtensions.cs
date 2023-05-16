using Win32;

namespace SyscallSummariser
{
    public static class MemoryExtensions
    {
        internal static bool IsExecutableMemory(this Kernel32.MemoryProtection protect)
        {
            return HasProtection(protect, Kernel32.MemoryProtection.EXECUTE) ||
                   HasProtection(protect, Kernel32.MemoryProtection.EXECUTE_READ) ||
                   HasProtection(protect, Kernel32.MemoryProtection.EXECUTE_READWRITE) ||
                   HasProtection(protect, Kernel32.MemoryProtection.EXECUTE_WRITECOPY);
        }

        internal static bool HasProtection(this Kernel32.MemoryProtection protect, Kernel32.MemoryProtection flag)
        {
            return (protect & flag) == flag;
        }
    }
}
