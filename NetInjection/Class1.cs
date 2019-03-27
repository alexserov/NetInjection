using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;
using NetInjection.Properties;

namespace NetInjection
{
    public static class Injector
    {
        static Injector()
        {
            File.WriteAllBytes("ManagedInjector32.dll", Resources.ManagedInjector32);
            File.WriteAllBytes("ManagedInjector64.dll", Resources.ManagedInjector64);
            File.WriteAllBytes("NetCoreInjector32.dll", Resources.NetCoreInjector32);
            File.WriteAllBytes("NetCoreInjector64.dll", Resources.NetCoreInjector64);

            File.WriteAllBytes("ManagedInjectorLauncher32.exe", Resources.ManagedInjectorLauncher32);
            File.WriteAllBytes("ManagedInjectorLauncher64.exe", Resources.ManagedInjectorLauncher64);
            File.WriteAllBytes("NetCoreInjectorLauncher32.exe", Resources.NetCoreInjectorLauncher32);
            File.WriteAllBytes("NetCoreInjectorLauncher64.exe", Resources.NetCoreInjectorLauncher64);

            File.WriteAllBytes("ProcessAnalyzer.exe", Resources.ProcessAnalyzer);
        }
        [SecuritySafeCritical]
        public static bool Inject(IntPtr windowHandle, Func<string, int> callback, string argument)
        {                        
            GetCallbackData(callback, out var assemblyName, out string assemblyFileFullName, out var className,
                out var methodName);
            GetProcessData(windowHandle, out var is32Bit, out var isNetCore, out var isValid);
            if (!isValid)
                return false;
            string runtime = isNetCore ? "NetCore" : "Managed";
            string bitness = is32Bit ? "32" : "64";
            string processName = $"{runtime}InjectorLauncher{bitness}.exe";

            Process.Start(new ProcessStartInfo()
            {
                FileName = processName,
                Arguments = $"{windowHandle.ToInt32()} \"{assemblyFileFullName}\" \"{className}\" \"{methodName}\" \"{argument}\""
            });
            return true;
        }
        [SecuritySafeCritical]
        private static void GetProcessData(IntPtr windowHandle, out bool is32Bit, out bool isNetCore, out bool isValid)
        {
            var proc = Process.Start(new ProcessStartInfo("ProcessAnalyzer.exe", Convert.ToString(windowHandle))
            {
                UseShellExecute = false
            });
            proc.WaitForExit();
            var eCode = proc.ExitCode;
            is32Bit = (eCode & 0x1) == 0x1;
            isNetCore = (eCode & 0x2) == 0x2;
            isValid = (eCode & 0x4) == 0x4;
        }

        static void GetCallbackData(Func<string, int> callback, out string assemblyName, out string assemblyFileFullName, out string className, out string methodName)
        {
            var mi = ValidateCallback(callback);
            methodName = mi.Name;
            
            var dt = mi.DeclaringType;
            className = dt.FullName;

            var asm = dt.Assembly;
            assemblyFileFullName = asm.Location;

            assemblyName = asm.GetName().Name;
        }

        static MethodInfo ValidateCallback(Func<string, int> callback)
        {
            var mi = callback.Method;
            if(!mi.IsPublic)
                throw new ArgumentException("Method must be public");
            if(!mi.IsStatic)
                throw new ArgumentException("Method must be static");
            return mi;
        }        
    }
}
