using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Security.Principal;
using static Win32.Advapi;
using static Win32.Ntdll;

namespace SyscallSummariser.Utilities
{
    class TokenUtils
    {
        private static readonly SafeProcessHandle hCurrentProcess = new SafeProcessHandle(new IntPtr(-1), false);
        public static bool ImpersonateSystem()
        {
            // borrow SYSTEM from winlogon.exe
            try {
                // System.Diagnostics will find winlogon and open a handle with PROCESS_ALL_ACCESS for us
                var winlogon = Process.GetProcessesByName("winlogon")[0];

                var hWinlogon = new SafeProcessHandle(winlogon.Handle, false);
                if(!OpenProcessToken(hWinlogon, TOKEN_DUPLICATE, out var hWinlogonToken))
                {
                    Log.ErrorWrite("OpenProcessToken(winlogon, TOKEN_DUPLICATE) failed");
                    return false;
                }
                if (!DuplicateToken(hWinlogonToken, SecurityImpersonation, out var hSystemToken))
                {
                    Log.ErrorWrite("DuplicateToken(winlogon, SecurityImpersonation) failed");
                    return false;
                }
                if(!ImpersonateLoggedOnUser(hSystemToken))
                {
                    Log.ErrorWrite("ImpersonateLoggedOnUser(winlogon) failed");
                    return false;
                }
            }
            catch
            {
                Log.ErrorWrite("failed to open winlogon handle");
                return false;
            }

            return WindowsIdentity.GetCurrent().IsSystem;
        }
    }
}