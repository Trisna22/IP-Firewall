#include "GraphicalUserInterface.h"
#include "Resources.h"

#include <Psapi.h>
#include <algorithm>
#include <TlHelp32.h>
#include <shellapi.h>
#pragma comment(lib, "Shell32.lib")


BOOL IsAdminstrator()
{
	BOOL fIsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdminGroup = NULL;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminGroup))
		return FALSE;
	if (!CheckTokenMembership(NULL, pAdminGroup, &fIsAdmin))
		return FALSE;

	//	Cleanup
	if (pAdminGroup)
	{
		FreeSid(pAdminGroup);
		pAdminGroup = NULL;
	}
	return fIsAdmin;
}
BOOL RetrieveAdminCreds()
{
	char szPath[MAX_PATH];
	if (GetModuleFileNameA(NULL, szPath, MAX_PATH))
	{
		SHELLEXECUTEINFOA sei = { sizeof(sei) };
		sei.lpVerb = "runas";
		sei.lpFile = szPath;
		sei.hwnd = NULL;
		sei.nShow = SW_SHOWNORMAL;
		if (!ShellExecuteExA(&sei))
		{
			DWORD dwErr = GetLastError();
			if (dwErr = ERROR_CANCELLED)
			{
				//	Elevation denied by user.
				return FALSE;
			}
			else
			{
				stringstream ss;
				ss << "\nAn error occured while elevating! Error code: " << dwErr << endl;
				MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
				return FALSE;
			}
		}
		else
		{
			return TRUE;
		}
	}
	else
	{
		MessageBoxA(NULL, "Failed to retrieve path to program!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
	return TRUE;
}
BOOL IsProgramAlreadyRunning(int PID)
{
	char s[MAX_PATH];
	GetModuleFileName(NULL, s, MAX_PATH);
	string nama = s;
	string ProgramName = nama.substr(nama.find_last_of("\\") + 1);
	transform(ProgramName.begin(), ProgramName.end(), ProgramName.begin(), ::tolower);

	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);
	if (Process32First(hProcess, &pe))
	{
		do
		{
			string name = pe.szExeFile;
			transform(name.begin(), name.end(), name.begin(), ::tolower);
			if (name == ProgramName && pe.th32ProcessID != PID)
			{
				CloseHandle(hProcess);
				return TRUE;
			}
		} while (Process32Next(hProcess, &pe));
		CloseHandle(hProcess);
		return FALSE;
	}
	else
	{
		stringstream ss;
		ss << "Failed to get Process32First() in ProcessIsRunning()! Error code: " << GetLastError() << endl << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	// Check if program is already running.
	if (IsProgramAlreadyRunning(GetCurrentProcessId()) == TRUE)
	{
		MessageBoxA(NULL, "Program is already running!\nClosing this program.",
			"IF: Warning", MB_OK | MB_ICONWARNING);
		return -1;
	}

	//	Check if we have admin rights.
	if (IsAdminstrator() == FALSE)
	{
		if (RetrieveAdminCreds() == TRUE)
		{
			//	Closing prorgam to let the elevated one go on.
			return 0;
		}
	}

	if (GraphicalUserInterface::RegisterWindowClass(hInstance) == false)
		return -1;
	if (GraphicalUserInterface::CreateMainWindow(hInstance, nCmdShow) == false)
		return -1;

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}