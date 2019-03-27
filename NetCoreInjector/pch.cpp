// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"
#include <unknwn.h>
#include "mscoree.h"
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.
typedef HRESULT(STDAPICALLTYPE* FnGetCLRRuntimeHost)(REFIID riid, IUnknown** pUnk);
static unsigned int WM_HOOKMESSAGE = ::RegisterWindowMessage(L"WM_HOOKMESSAGE");
static HHOOK hHook;
EXTERN_C __declspec(dllexport) LRESULT CALLBACK CallWndHoocProc(int nCode, WPARAM wparam, LPARAM lparam)
{	
	if (nCode == HC_ACTION) {
		CWPSTRUCT* msg = (CWPSTRUCT*)lparam;
		if (msg != NULL && msg->message == WM_HOOKMESSAGE) {			
			HMODULE coreCLRModule = ::GetModuleHandle(L"coreclr.dll");
			if(coreCLRModule)
			{
				FnGetCLRRuntimeHost pfnGetCLRRuntimeHost = (FnGetCLRRuntimeHost)::GetProcAddress(coreCLRModule, "GetCLRRuntimeHost");
				if(pfnGetCLRRuntimeHost)
				{					
					ICLRRuntimeHost* clrRuntimeHost = nullptr;
					HRESULT hr = pfnGetCLRRuntimeHost(IID_ICLRRuntimeHost, (IUnknown * *)& clrRuntimeHost);
					if (clrRuntimeHost) {
						hr = clrRuntimeHost->Start();
						auto acmRemote = (wchar_t*)msg->wParam;
						std::wstring acma = acmRemote;
						DWORD result = 0;
						std::wstring temp;
						std::vector<std::wstring> parts;
						std::wstringstream wss(acma);
						while (std::getline(wss, temp, L'$'))
							parts.push_back(temp);
						hr = clrRuntimeHost->ExecuteInDefaultAppDomain(parts[0].c_str(), parts[1].c_str(), parts[2].c_str(), parts[3].c_str(), &result);
						if(hr!=S_OK)
						{
							__debugbreak();
						}
					}
				}					
			}
		}
	}
	return CallNextHookEx(hHook, nCode, wparam, lparam);
}

__declspec(dllexport)
LRESULT __stdcall Launch(wchar_t* argv[])
{
	std::wstring assembly = argv[2];
	std::wstring className = argv[3];
	std::wstring methodName = argv[4];
	std::wstring argument = argv[5];

	std::wstring assemblyClassAndMethod = assembly + L"$" + className + L"$" + methodName + L"$" + argument;

	HINSTANCE hinstDLL;
	auto windowHandleInt = _wtoi(argv[1]);
	HWND wndHandle = (HWND)windowHandleInt;

	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, LPCTSTR(&CallWndHoocProc), &hinstDLL))
	{
		DWORD processID = 0;
		DWORD threadID = ::GetWindowThreadProcessId(wndHandle, &processID);
		if (processID)
		{
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
			if (hProcess)
			{
				int buffLen = (assemblyClassAndMethod.length() + 1) * sizeof(wchar_t);
				void* acmRemote = VirtualAllocEx(hProcess, NULL, buffLen, MEM_COMMIT, PAGE_READWRITE);

				if (acmRemote)
				{
					WriteProcessMemory(hProcess, acmRemote, assemblyClassAndMethod.c_str(), buffLen, NULL);
					hHook = ::SetWindowsHookEx(WH_CALLWNDPROC, &CallWndHoocProc, hinstDLL, threadID);

					if (hHook)
					{
						::SendMessage(wndHandle, WM_HOOKMESSAGE, (WPARAM)acmRemote, 0);
						::UnhookWindowsHookEx(hHook);
					}
					VirtualFreeEx(hProcess, acmRemote, 0, MEM_RELEASE);
				}
				CloseHandle(hProcess);
			}

		}

		::FreeLibrary(hinstDLL);
		return 0;
	}
}