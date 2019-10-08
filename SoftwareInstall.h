#pragma once

#include "stdafx.h"
#include "XMLWriter.h"
#include "XMLReader.h"

class SoftwareInstall
{
public:
	bool InstallSoftware(string, string);
private:
	bool IsAdmin();
	bool CheckFiles(string, string);

};

/*   Installs the software for the first run.   */
bool SoftwareInstall::InstallSoftware(string SSID, string MAC)
{
	if (IsAdmin() == false)
	{
		MessageBox(0, "Failed to install the software for first run!\nREASON: No admin rights",
			"IF: Warning", MB_OK | MB_ICONWARNING);
		return false;
	}

	if (CheckFiles(SSID, MAC) == false)
		return false;

	return true;
}

/*   Checks if we have admin rights.   */
bool SoftwareInstall::IsAdmin()
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

/*   Checks the essential files for IPFirewall program.   */
bool SoftwareInstall::CheckFiles(string SSID, string MAC)
{
	string ProgramFiles = getenv("ProgramFiles");

	//	Check if the main folder exists.
	string s = ProgramFiles + "\\IP Firewall\\";
	if (_access(s.c_str(), 00) == -1)
	{
		int res = MessageBox(0, "The IP Firewall resources don't exists!\nWant to install the software first?", "IF: Warning", MB_YESNO | MB_ICONWARNING);
		if (res != IDYES)
			return false;

		if (CreateDirectoryA(s.c_str(), 0) == false)
		{
			string msg = "Failed to create a folder in the program files directory! Error code: " + to_string(GetLastError());
			MessageBox(0, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
			return false;
		}
	}

	//	Check if the wifi profile exists.
	string s2 = ProgramFiles + "\\IP Firewall\\Profile_" + SSID + ".config";
	if (_access(s2.c_str(), 00) == -1)
	{
		ofstream off(s2.c_str());
		if (!off.is_open())
		{
			MessageBox(0, "Failed to create the configuration file for the current wifi profile!", "IF: Error", MB_OK | MB_ICONERROR);
			return false;
		}
		off.close();
	}

	return true;
}