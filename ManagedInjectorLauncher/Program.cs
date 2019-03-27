// (c) Copyright Cory Plotts.
// This source is subject to the Microsoft Public License (Ms-PL).
// Please see http://go.microsoft.com/fwlink/?LinkID=131993 for details.
// All other rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ManagedInjector;

namespace ManagedInjectorLauncher
{
	class Program
	{
		static void Main(string[] args)
		{            

			var windowHandle = (IntPtr)Int64.Parse(args[0]);
			var assemblyName = args[1];
			var className = args[2];
			var methodName = args[3];
            var arguments = args[4];

            Injector.Launch(windowHandle, assemblyName, className, methodName, arguments);

            //check to see that it was injected, and if not, retry with the main window handle.
            var process = GetProcessFromWindowHandle(windowHandle);
            if (process != null && !CheckInjectedStatus(process) && process.MainWindowHandle != windowHandle)
            {
                Injector.Launch(process.MainWindowHandle, assemblyName, className, methodName, arguments);
                CheckInjectedStatus(process);
            }
		}

        private static Process GetProcessFromWindowHandle(IntPtr windowHandle)
        {
            int processId;
            GetWindowThreadProcessId(windowHandle, out processId);
            if (processId == 0)
            {
                return null;
            }

            return Process.GetProcessById(processId);
        }

        private static bool CheckInjectedStatus(Process process)
        {
            bool containsFile = false;
            process.Refresh();
            foreach (ProcessModule module in process.Modules)
            {
                if (module.FileName.Contains("ManagedInjector"))
                {
                    containsFile = true;
                }
            }
            if (containsFile)
            {
            }
            else
            {
            }

            return containsFile;
        }

        [DllImport("user32.dll")]
        public static extern int GetWindowThreadProcessId(IntPtr hwnd, out int processId);
	}
}
