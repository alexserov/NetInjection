using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace ProcessAnalyzer
{
    class Program
    {
        static int Main(string[] args)
        {
            var windowHandle = new IntPtr(Int32.Parse(args[0]));
            var proc = GetProcessFromWindowHandle(windowHandle);
            var is32Bit = IsWow64Process(proc.Handle, out var resultIsWow64Process) && resultIsWow64Process ? 0x1 : 0x0;
            var isNetCore = 0x0;
            var isValid = 0x0;
            foreach (var module in GetModules(proc.Id))
            {
                if (module.szModule.Contains("coreclr"))
                {
                    isNetCore = 0x2;
                    isValid = 0x4;
                    break;
                }
                if (module.szModule.Contains("mscor"))
                {
                    isNetCore = 0x0;
                    isValid = 0x4;
                }
            }

            return is32Bit | isNetCore | isValid;
        }
        [SecuritySafeCritical]
        static Process GetProcessFromWindowHandle(IntPtr windowHandle)
        {
            int processId;
            GetWindowThreadProcessId(windowHandle, out processId);
            if (processId == 0)
            {
                return null;
            }

            return Process.GetProcessById(processId);
        }
        static IEnumerable<MODULEENTRY32> GetModules(int processId)
        {
            var me32 = new MODULEENTRY32();
            var hModuleSnap =
                CreateToolhelp32Snapshot(SnapshotFlags.Module | SnapshotFlags.Module32, processId);
            if (!hModuleSnap.IsInvalid)
            {
                using (hModuleSnap)
                {
                    me32.dwSize = (uint)Marshal.SizeOf(me32);
                    if (Module32First(hModuleSnap, ref me32))
                    {
                        do
                        {
                            yield return me32;
                        } while (Module32Next(hModuleSnap, ref me32));
                    }
                }
            }
            else
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEENTRY32
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            readonly IntPtr modBaseAddr;
            public uint modBaseSize;
            readonly IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
        }
        public class ToolHelpHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            ToolHelpHandle()
                : base(true) { }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hHandle);
        [DllImport("kernel32.dll")]
        public static extern bool Module32First(ToolHelpHandle hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll")]
        public static extern bool Module32Next(ToolHelpHandle hSnapshot, ref MODULEENTRY32 lpme);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern ToolHelpHandle CreateToolhelp32Snapshot(SnapshotFlags dwFlags, int th32ProcessID);
        [DllImport("user32.dll")]
        static extern int GetWindowThreadProcessId(IntPtr hwnd, out int processId);
        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);
    }
}
