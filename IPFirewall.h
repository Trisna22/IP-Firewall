#pragma once
#include "stdafx.h"
#include "SoftwareInstall.h"
#include "XMLReader.h"

#define WLAN_ERROR				"ERROR_WLAN_FAILED"
#define WLAN_NOT_CONNECTED		"WLAN_NOT_CONNECTED"
#define INVALID_IP				"INVALID_IP_ADDRESS"
#define BYTE_IPADDR_ARRLEN		4
#define STR_IPADDR_LEN			32
#define VISTA_SUBNET_MASK		0xffffffff

class IPFirewall
{
public:
	IPFirewall();
	~IPFirewall();
	BOOL StartFirewall();
	BOOL InitializeFirewall();
	BOOL StopFirewall();
	bool IsFirewallReady();

	string WIFI_SSID = WLAN_ERROR;
	string WIFI_MAC = WLAN_ERROR;
private:
	bool IsReady = false;
	bool IsFirewallRunning = false;
	bool GotPermissions();
	string RetrieveConnectedWifiSSID();
	string RetrieveConnectedWifiMAC();
};

/*   Constructor of IPFirewall class.   */
IPFirewall::IPFirewall()
{
	if (GotPermissions() == false)
	{
		MessageBox(0, "We need admin priveledges to proceed or to install software!", "IF: Warning", MB_OK | MB_ICONWARNING);
		return;
	}

	WIFI_SSID = RetrieveConnectedWifiSSID();
	WIFI_MAC = RetrieveConnectedWifiMAC();
	if (WIFI_SSID == WLAN_ERROR || WIFI_SSID == WLAN_NOT_CONNECTED)
	{
		string msg = "Not connected to wifi or failed to retrieve data! Error code: " + to_string(GetLastError());
		MessageBox(0, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return;
	}

	SoftwareInstall install;
	if (install.InstallSoftware(WIFI_SSID, WIFI_MAC) == false)
	{
		MessageBox(0, "Failed to install the software for continuing!", "IF: Warning", MB_OK | MB_ICONWARNING);
		return;
	}

	IsReady = true;
}

/*   Initializes the IPFirewalll class in case it failed the first time.   */
BOOL IPFirewall::InitializeFirewall()
{
	if (GotPermissions() == false)
	{
		MessageBox(0, "We need admin priveledges to proceed!", "IF: Warning", MB_OK | MB_ICONWARNING);
		return false;
	}

	WIFI_SSID = RetrieveConnectedWifiSSID();
	WIFI_MAC = RetrieveConnectedWifiMAC();
	if (WIFI_SSID == WLAN_ERROR || WIFI_SSID == WLAN_NOT_CONNECTED)
	{
		string msg = "Not connected to wifi or failed to retrieve data! Error code: " + to_string(GetLastError());
		MessageBox(0, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return false;
	}

	SoftwareInstall install;
	if (install.InstallSoftware(WIFI_SSID, WIFI_MAC) == false)
	{
		MessageBox(0, "Failed to install the software for continuing!", "IF: Warning", MB_OK | MB_ICONWARNING);
		return false;
	}

	IsReady = true;
	return true;
}

/*   Deconstructor of IPFirewall class.   */
IPFirewall::~IPFirewall()
{

}

/*   Starts firewall blocking IP addresses.   */
BOOL IPFirewall::StartFirewall()
{
	return false;
}

/*   Stops firewall blocking IP addresses.   */
BOOL IPFirewall::StopFirewall()
{

	return false;
}

/*   Checks if the program got the permissions to create/change a firewall.   */
bool IPFirewall::GotPermissions()
{
	BOOL fIsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdminGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminGroup))
		return false;

	if (!CheckTokenMembership(NULL, pAdminGroup, &fIsAdmin))
		return false;

	//	Cleanup.
	if (pAdminGroup)
	{
		FreeSid(pAdminGroup);
		pAdminGroup = NULL;
	}

	return fIsAdmin;
}

/*   Checks if the firewall class is initialized succesfully.   */
bool IPFirewall::IsFirewallReady()
{
	return IsReady;
}

/*   Retrieves important interface settings.   */
string IPFirewall::RetrieveConnectedWifiSSID()
{
	HANDLE hClient = NULL;
	DWORD dwMaxClient = 2;
	DWORD dwCurVersion = 0;
	DWORD dwResult = 0;
	DWORD dwRetVal = 0;
	int iRet = 0;
	WCHAR GuidString[39] = { 0 };
	unsigned int i, k;
	PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	PWLAN_INTERFACE_INFO pIfInfo = NULL;
	PWLAN_CONNECTION_ATTRIBUTES pConnectInfo = NULL;
	DWORD connectInfoSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
	WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_invalid;

	//	Initializing Wlan
	dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
	if (dwResult != ERROR_SUCCESS)
	{
		stringstream ss;
		ss << "Failed to initialize wlan! Error code: " << dwResult << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return "ERROR_WLAN_FAILED";
	}

	//	Enumerating interfaces
	dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
	if (dwResult != ERROR_SUCCESS)
	{
		stringstream ss;
		ss << "Failed to enumerate wlan interfaces! Error code: " << dwResult << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return "ERROR_WLAN_FAILED";
	}

	//	Get the connected interfaces
	for (int i = 0; i < (int)pIfList->dwNumberOfItems; i++)
	{
		pIfInfo = (WLAN_INTERFACE_INFO*)& pIfList->InterfaceInfo[i];
		if (pIfInfo->isState == wlan_interface_state_connected)
		{
			dwResult = WlanQueryInterface(hClient, &pIfInfo->InterfaceGuid,
				wlan_intf_opcode_current_connection, NULL, &connectInfoSize,
				(PVOID*)& pConnectInfo, &opCode);
			if (dwResult != ERROR_SUCCESS)
			{
				stringstream ss;
				ss << "Failed to query interface of our connected interface! Error code: " << dwResult << endl;
				MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
				return "ERROR_WLAN_FAILED";
			}

			//	Retrieve SSID
			string SSID;
			for (int k = 0; k < (int)pConnectInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength; k++)
			{
				WCHAR str[MAX_PATH];
				wsprintfW(str, L"%c", (int)pConnectInfo->wlanAssociationAttributes.dot11Ssid.ucSSID[k]);
				wstring s = str;
				SSID += string(s.begin(), s.end());
			}

			if (pConnectInfo != NULL)
			{
				WlanFreeMemory(pConnectInfo);
				pConnectInfo = NULL;
			}
			if (pIfList != NULL)
			{
				WlanFreeMemory(pIfList);
				pIfList = NULL;
			}
			return SSID;
		}
	}
	if (pConnectInfo != NULL)
	{
		WlanFreeMemory(pConnectInfo);
		pConnectInfo = NULL;
	}
	if (pIfList != NULL)
	{
		WlanFreeMemory(pIfList);
		pIfList = NULL;
	}
	MessageBoxA(NULL, "Not connected to any wifi interface!", "IPS: Warning", MB_OK | MB_ICONWARNING);
	return "WLAN_NOT_CONNECTED";
}
string IPFirewall::RetrieveConnectedWifiMAC()
{
	HANDLE hClient = NULL;
	DWORD dwMaxClient = 2;
	DWORD dwCurVersion = 0;
	DWORD dwResult = 0;
	DWORD dwRetVal = 0;
	int iRet = 0;
	WCHAR GuidString[39] = { 0 };
	unsigned int i, k;
	PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	PWLAN_INTERFACE_INFO pIfInfo = NULL;
	PWLAN_CONNECTION_ATTRIBUTES pConnectInfo = NULL;
	DWORD connectInfoSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
	WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_invalid;

	//	Initializing Wlan
	dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
	if (dwResult != ERROR_SUCCESS)
	{
		stringstream ss;
		ss << "Failed to initialize wlan! Error code: " << dwResult << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return "ERROR_WLAN_FAILED";
	}

	//	Enumerating interfaces
	dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
	if (dwResult != ERROR_SUCCESS)
	{
		stringstream ss;
		ss << "Failed to enumerate wlan interfaces! Error code: " << dwResult << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return "ERROR_WLAN_FAILED";
	}

	//	Get the connected interface
	for (int i = 0; i < (int)pIfList->dwNumberOfItems; i++)
	{
		pIfInfo = (WLAN_INTERFACE_INFO*)& pIfList->InterfaceInfo[i];
		if (pIfInfo->isState == wlan_interface_state_connected)
		{
			dwResult = WlanQueryInterface(hClient, &pIfInfo->InterfaceGuid,
				wlan_intf_opcode_current_connection, NULL, &connectInfoSize,
				(PVOID*)& pConnectInfo, &opCode);
			if (dwResult != ERROR_SUCCESS)
			{
				stringstream ss;
				ss << "Failed to query interface of our connected interface! Error code: " << dwResult << endl;
				MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
				return "ERROR_WLAN_FAILED";
			}

			//	Retrieve MAC address
			string MAC_ADDR;
			for (int k = 0; k < sizeof(pConnectInfo->wlanAssociationAttributes.dot11Bssid); k++)
			{
				WCHAR str[5];
				if (k == 5)
				{
					wsprintfW(str, L"%.2X", pConnectInfo->wlanAssociationAttributes.dot11Bssid[k]);
					wstring s = str;
					MAC_ADDR += string(s.begin(), s.end());
					break;
				}
				else
				{
					wsprintfW(str, L"%.2X:", pConnectInfo->wlanAssociationAttributes.dot11Bssid[k]);
					wstring s = str;
					MAC_ADDR += string(s.begin(), s.end());
				}
			}
			if (pConnectInfo != NULL)
			{
				WlanFreeMemory(pConnectInfo);
				pConnectInfo = NULL;
			}
			if (pIfList != NULL)
			{
				WlanFreeMemory(pIfList);
				pIfList = NULL;
			}
			return MAC_ADDR;
		}
	}
	if (pConnectInfo != NULL)
	{
		WlanFreeMemory(pConnectInfo);
		pConnectInfo = NULL;
	}
	if (pIfList != NULL)
	{
		WlanFreeMemory(pIfList);
		pIfList = NULL;
	}
	MessageBoxA(NULL, "Not connected to any wifi interface!", "IPS: Warning", MB_OK | MB_ICONWARNING);
	return "WLAN_NOT_CONNECTED";
}