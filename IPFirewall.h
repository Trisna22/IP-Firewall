#pragma once
#include "stdafx.h"
#include "SoftwareInstall.h"
#include "XMLReader.h"

#include <vector>

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

	bool IsFirewallRunning = false;
	string WIFI_SSID = WLAN_ERROR;
	string WIFI_MAC = WLAN_ERROR;

private:
	bool IsReady = false;
	bool ListInitialized = false;
	typedef struct _IPFILTERINFO
	{
		BYTE bIpAddrToBlock[BYTE_IPADDR_ARRLEN];
		ULONG uHexAddrToBlock;
		UINT64 u64VistaFilterId;
	} IPFILTERINFO, * PIPFILTERINFO;
	typedef std::list<IPFILTERINFO> IPFILTERINFOLIST;
	IPFILTERINFOLIST m_lstFilters;
	HANDLE m_hEngineHandle;
	GUID m_subLayerGUID;

	vector <string>IP_LIST;

	bool GotPermissions();
	string RetrieveConnectedWifiSSID();
	string RetrieveConnectedWifiMAC();
	void AddToList(string);
	BOOL ParseIPAddrString(string, UINT, BYTE*, UINT, ULONG&);
	DWORD CreateDelete_Interfaces(BOOL);
	DWORD AddRemove_Filter(BOOL);
	DWORD BindUnBind_Interface(BOOL);

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
	if (GotPermissions() == false)
	{
		MessageBox(0, "You need to have permission from the adminstrator to start the firewall!", "FI: Warning", MB_OK | MB_ICONWARNING);
		return false;
	}

	string env = getenv("ProgramFiles");
	string path = env + "\\IP Firewall\\Profile_" + WIFI_SSID + ".config";

	//	Check if the list is already set.
	if (ListInitialized == false)
	{
		//	Open the list.
		XMLReader reader(path);
		if (!reader.IsReady())
		{
			MessageBox(0, "XMLReader failed to open!", "IF: Error", MB_OK | MB_ICONERROR);
			return false;
		}

		//	List trough IP addresses and add them to the list.
		for (int i = 0; i < reader.RetrieveIPAddressesInFile(); i++)
		{
			string IP = reader.RetrieveIP(i);
			if (IP == "IP_NOT_FOUND")
				continue;

			IP_LIST.push_back(IP);
			AddToList(IP);
			ListInitialized = true;
		}
	}

	//	Create the packet filter interface.
	BOOL bStarted = FALSE;
	if (ERROR_SUCCESS == CreateDelete_Interfaces(TRUE))
	{
		//	Bind packet filter interface.
		if (ERROR_SUCCESS == BindUnBind_Interface(TRUE))
		{
			AddRemove_Filter(TRUE);
			IsFirewallRunning = true;
			bStarted = TRUE;
		}
		else
		{
			MessageBox(0, "Failed to bind the packet filter interface!", "IF: Error", MB_OK | MB_ICONERROR);
		}
	}
	else
	{
		MessageBox(0, "Failed to create the packet filter interface!", "IF: Error", MB_OK | MB_ICONERROR);
	}
	return bStarted;
}

/*   Stops firewall blocking IP addresses.   */
BOOL IPFirewall::StopFirewall()
{
	BOOL bStopped = FALSE;

	//	Remove all filters.
	AddRemove_Filter(FALSE);
	m_lstFilters.clear();
	ListInitialized = FALSE;

	//	Unbind from packet filter interface.
	if (ERROR_SUCCESS != BindUnBind_Interface(FALSE))
	{
		MessageBoxA(NULL, "Failed to unbind from packet filter interface!", "IF: Error", MB_OK | MB_ICONERROR);
	}

	//	Delete packet filter interface.
	if (ERROR_SUCCESS == CreateDelete_Interfaces(FALSE))
	{
		bStopped = TRUE;
	}
	else
	{
		MessageBoxA(NULL, "Failed to delete filter interface!", "IF: Error", MB_OK | MB_ICONERROR);
	}

	if (bStopped == TRUE)
		IsFirewallRunning = false;

	return bStopped;
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

/*   Adds IP to blocked list.   */
void IPFirewall::AddToList(string IP)
{
	IPFILTERINFO stIPFilter = {0};

	//	Get byte array format and hex format IP address from string format.
	ParseIPAddrString(IP, lstrlenA(IP.c_str()),
		stIPFilter.bIpAddrToBlock,
		BYTE_IPADDR_ARRLEN,
		stIPFilter.uHexAddrToBlock);

	//	Push the IP address information to list.
	m_lstFilters.push_back(stIPFilter);
}

/*   Parses the heximal and byte array format from string.   */
BOOL IPFirewall::ParseIPAddrString(string szIpAddr, UINT nStrLen, BYTE* pbHostOrder, UINT nByteLen, ULONG& uHexAddr)
{
	BOOL bRet = TRUE;
	UINT i = 0;
	UINT j = 0;
	UINT nPack = 0;
	char szTemp[2];

	//	Build byte array format from string format
	for (; (i < nStrLen) && (j < nByteLen);)
	{
		if ('.' != szIpAddr[i])
		{
			StringCchPrintfA(szTemp, 2, "%c", szIpAddr[i]);
			nPack = (nPack * 10) + atoi(szTemp);
		}
		else
		{
			pbHostOrder[j] = nPack;
			nPack = 0;
			j++;
		}
		i++;
	}
	if (j < nByteLen)
	{
		pbHostOrder[j] = nPack;

		// Build hex format from byte array format.
		for (j = 0; j < nByteLen; j++)
		{
			uHexAddr = (uHexAddr << 8) + pbHostOrder[j];
		}

	}
	return bRet;
}

/*   Creates or deletes the packet filter interface.   */
DWORD IPFirewall::CreateDelete_Interfaces(BOOL bCreate)
{
	DWORD dwFwApiRetCode = ERROR_BAD_COMMAND;
	if (bCreate == TRUE)
	{
		//	Create packet filter interface
		dwFwApiRetCode = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT,
			NULL, NULL, &m_hEngineHandle);
	}
	else
	{
		if (NULL != m_hEngineHandle)
		{
			//	Close packet filter interface
			dwFwApiRetCode = FwpmEngineClose0(m_hEngineHandle);
			m_hEngineHandle = NULL;
		}
	}
	return dwFwApiRetCode;
}

/*   Adds or removes filter from interface.   */
DWORD IPFirewall::AddRemove_Filter(BOOL bAdd)
{
	DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	if (bAdd == TRUE)
	{
		//	Add filter
		if (m_lstFilters.size())
		{
			IPFILTERINFOLIST::iterator itFilter;
			for (itFilter = m_lstFilters.begin(); itFilter != m_lstFilters.end(); itFilter++)
			{
				if ((NULL != itFilter->bIpAddrToBlock) && (0 != itFilter->uHexAddrToBlock))
				{
					FWPM_FILTER0 Filter = { 0 };
					FWPM_FILTER_CONDITION0 Condition = { 0 };
					FWP_V4_ADDR_AND_MASK AddrMask = { 0 };

					//	Prepare filter condition
					Filter.subLayerKey = m_subLayerGUID;
					Filter.displayData.name = (wchar_t*)L"IP Firewall";
					Filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
					Filter.action.type = FWP_ACTION_BLOCK;
					Filter.weight.type = FWP_EMPTY;
					Filter.filterCondition = &Condition;
					Filter.numFilterConditions = 1;

					// Remote IP address should match itFilters->uHexAddrToBlock.
					Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
					Condition.matchType = FWP_MATCH_EQUAL;
					Condition.conditionValue.type = FWP_V4_ADDR_MASK;
					Condition.conditionValue.v4AddrMask = &AddrMask;

					//	Add IP address to be blocked
					AddrMask.addr = itFilter->uHexAddrToBlock;
					AddrMask.mask = VISTA_SUBNET_MASK;

					// Add filter condition to our interface. Save filter id in itFilters->u64VistaFilterId.
					dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
						&Filter,
						NULL,
						&(itFilter->u64VistaFilterId));
				}
			}
		}
	}
	else
	{
		//	Remove filter
		if (m_lstFilters.size())
		{
			IPFILTERINFOLIST::iterator itFilter;
			for (itFilter = m_lstFilters.begin(); itFilter != m_lstFilters.end(); itFilter++)
			{
				if ((NULL != itFilter->bIpAddrToBlock) && (NULL != itFilter->uHexAddrToBlock))
				{
					//	Delete all previously added filters.
					dwFwAPiRetCode = FwpmFilterDeleteById0(m_hEngineHandle, itFilter->u64VistaFilterId);
					itFilter->u64VistaFilterId = NULL;
				}
			}
		}
	}
	return dwFwAPiRetCode;
}

/*   Binds or unbinds the packet filter.   */	
DWORD IPFirewall::BindUnBind_Interface(BOOL bBind)
{
	DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	if (bBind == TRUE)
	{
		RPC_STATUS rpcStatus = { 0 };
		FWPM_SUBLAYER0 SubLayer = { 0 };

		//	Create a GUID for our packet filter layer.
		rpcStatus = UuidCreate(&SubLayer.subLayerKey);
		if (NO_ERROR == rpcStatus)
		{
			//	Save GUID
			CopyMemory(&m_subLayerGUID,
				&SubLayer.subLayerKey,
				sizeof(SubLayer.subLayerKey));
			//	Populate packet filter layer information
			SubLayer.displayData.name = (wchar_t*)L"IP Firwall";
			SubLayer.displayData.description = (wchar_t*)L"IP Firewall from Trisna Quebe";
			SubLayer.flags = 0;
			SubLayer.weight = 0x100;

			// Add packet filter to our interface.
			dwFwAPiRetCode = ::FwpmSubLayerAdd0(m_hEngineHandle,
				&SubLayer,
				NULL);
		}
	}
	else
	{
		//	Delete packet filter layer from interface.
		dwFwAPiRetCode = FwpmSubLayerDeleteByKey0(m_hEngineHandle, &m_subLayerGUID);
		ZeroMemory(&m_subLayerGUID, sizeof(GUID));
	}
	return dwFwAPiRetCode;
}