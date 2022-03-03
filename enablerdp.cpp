#include <windows.h>
#include <netfw.h>
#include <IPHlpApi.h>
#include <atlcomcli.h>
#include <versionhelpers.h>
#include <ShlObj_core.h>
// #include <bcrypt.h> 
#pragma comment(lib, "Iphlpapi.lib") // IPHlpApi.h

#define NET_FW_IP_PROTOCOL_TCP_NAME L"TCP"
#define NET_FW_IP_PROTOCOL_UDP_NAME L"UDP"

#define NET_FW_RULE_DIR_IN_NAME L"In"
#define NET_FW_RULE_DIR_OUT_NAME L"Out"

#define NET_FW_RULE_ACTION_BLOCK_NAME L"Block"
#define NET_FW_RULE_ACTION_ALLOW_NAME L"Allow"

#define NET_FW_RULE_ENABLE_IN_NAME L"TRUE"
#define NET_FW_RULE_DISABLE_IN_NAME L"FALSE"

#define TERMINAL_SERVER_KEY _T("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\")
#define GLASS_SESSION_ID    _T("GlassSessionId")

// Forward declarations
HRESULT     WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);

// 对于当前活动的防火墙配置文件，显示防火墙是打开还是关闭
HRESULT GetCurrentFirewallState(__in INetFwPolicy2* pNetFwPolicy2)
{
	HRESULT hr = S_FALSE;
	long    CurrentProfilesBitMask = 0;
	VARIANT_BOOL bActualFirewallEnabled = VARIANT_FALSE;
	struct ProfileMapElement
	{
		NET_FW_PROFILE_TYPE2 Id;
		LPCWSTR Name;
	};
	ProfileMapElement ProfileMap[3];
	ProfileMap[0].Id = NET_FW_PROFILE2_DOMAIN;
	ProfileMap[0].Name = L"Domain";
	ProfileMap[1].Id = NET_FW_PROFILE2_PRIVATE;
	ProfileMap[1].Name = L"Private";
	ProfileMap[2].Id = NET_FW_PROFILE2_PUBLIC;
	ProfileMap[2].Name = L"Public";

	hr = pNetFwPolicy2->get_CurrentProfileTypes(&CurrentProfilesBitMask);
	if (FAILED(hr))
	{
		wprintf(L"[-] Failed to get CurrentProfileTypes. Error: %x.\n", hr);
		goto CLEANUP;
	}
	for (int i = 0; i < 3; i++)
	{
		if (CurrentProfilesBitMask & ProfileMap[i].Id)
		{
			hr = pNetFwPolicy2->get_FirewallEnabled(ProfileMap[i].Id, &bActualFirewallEnabled);
			if (FAILED(hr))
			{
				wprintf(L"[-] Failed to get FirewallEnabled settings for %s profile. Error: %x.\n", ProfileMap[i].Name, hr);
				goto CLEANUP;
			}

			if (bActualFirewallEnabled) {
				wprintf(L"[*] On %s profile (Current) : Firewall state is %s\n", ProfileMap[i].Name, (bActualFirewallEnabled ? L"ON" : L"OFF"));
				return 4;
			}
			else {
				wprintf(L"[*] On %s profile (Current) : Firewall state is %s\n", ProfileMap[i].Name, (bActualFirewallEnabled ? L"ON" : L"OFF"));
				return 3;
			}
		}
	}
CLEANUP:
	return hr;
}

/// <summary>
/// 检查防火墙规则组是否启用
/// </summary>
/// <param name="pNetFwPolicy2"></param>
/// <param name="RuleGroup"></param>
/// <returns></returns>
HRESULT IsRuleGroupEnabled(__in INetFwPolicy2* pNetFwPolicy2, wchar_t* RuleGroup)
{

	HRESULT hr = S_OK;
	VARIANT_BOOL bActualEnabled = VARIANT_FALSE;

	BSTR GroupName = SysAllocString(RuleGroup);
	if (NULL == GroupName)
	{
		wprintf(L"[-] ERROR: Insufficient memory\n");
		goto Cleanup;
	}

	// 检测规则组是否在专用配置和公用配置中启用
	hr = pNetFwPolicy2->IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC, GroupName, &bActualEnabled);

	if (SUCCEEDED(hr))
	{
		if (VARIANT_TRUE == bActualEnabled && S_OK == hr)
		{
			wprintf(L"[+] Rule Group currently enabled on both public and private profiles\n");
		}
		else if (VARIANT_TRUE == bActualEnabled && S_FALSE == hr)
		{
			wprintf(L"[+] Rule Group currently enabled on either public or private profile but not both\n");
		}
		else if (VARIANT_FALSE == bActualEnabled)
		{
			wprintf(L"[-] Rule Group currently disabled on both public and private profiles\n");
		}
	}
	else
	{
		wprintf(L"[-] Failed calling API IsRuleGroupCurrentlyEnabled. Error: 0x %x.\n", hr);
		goto Cleanup;
	}
Cleanup:
	SysFreeString(GroupName);
	return hr;
}

/// <summary>
/// 检查防火墙状态
/// </summary>
/// <returns>TRUE:开启，FLASE:关闭</returns>
BOOL CheckFireWallState() {
	int res = 0;
	HRESULT hr = S_OK;
	HRESULT hrComInit = S_OK;
	INetFwPolicy2* pNetFwPolicy2 = NULL;
	// Initialize COM.
	hrComInit = CoInitializeEx(
		0,
		COINIT_APARTMENTTHREADED
	);

	// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
	if (hrComInit != RPC_E_CHANGED_MODE)
	{
		if (FAILED(hrComInit))
		{
			printf("CoInitializeEx failed: 0x%08lx\n", hrComInit);
			goto Cleanup;
		}
	}

	// Retrieve INetFwPolicy2
	hr = WFCOMInitialize(&pNetFwPolicy2);
	if (FAILED(hr))
	{
		goto Cleanup;
	}
	// 检查是否开启了防火墙
	res = GetCurrentFirewallState(pNetFwPolicy2);
	if (res == 3) {
		// 防火墙关闭
		goto Cleanup;
	}
	if (pNetFwPolicy2 != NULL)
	{
		pNetFwPolicy2->Release();
	}
	return TRUE;
Cleanup:
	// Release the INetFwPolicy2 object
	if (pNetFwPolicy2 != NULL)
	{
		pNetFwPolicy2->Release();
	}
	return FALSE;
}

/// <summary>
/// 设置防火墙规则
/// </summary>
/// <param name="P"></param>
/// <returns></returns>
BOOL __cdecl SetFireWall(int P = NULL)
{
	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;
	int port = 0;
	int res = 0;
	long           index = 0;
	SAFEARRAY* pSa = NULL;
	INetFwPolicy2* pNetFwPolicy2 = NULL;
	INetFwRules* pFwRules = NULL;
	INetFwRule* pFwRule = NULL;
	if (P != NULL) {
		port = P;
	}
	else {
		return FALSE;
	}

	// 规则名称
	wchar_t RuleName[200] = L"";
	// 规则描述
	wchar_t RuleDescription[200] = L"";
	// 规则组名
	wchar_t RuleGroup[100] = L"";
	// 规则端口
	wchar_t RuleLPorts[11] = L"";

	swprintf(RuleName, 200, L"远程桌面 - RemoteFX (TCP-In) -Remote");
	swprintf(RuleDescription, 200, L"用于远程桌面服务的入站规则，以允许 RDP 通信。[TCP %d]", port);
	swprintf(RuleGroup, 100, L"远程桌面");
	swprintf(RuleLPorts, 11, L"%d", port);

	BSTR bstrRuleName = SysAllocString(RuleName);
	BSTR bstrRuleDescription = SysAllocString(RuleDescription);
	BSTR bstrRuleGroup = SysAllocString(RuleGroup);
	BSTR bstrRuleLPorts = SysAllocString(RuleLPorts);

	// Error checking for BSTR allocations
	if (NULL == bstrRuleName) { printf("Failed to allocate bstrRuleName\n"); goto Cleanup; }
	if (NULL == bstrRuleDescription) { printf("Failed to allocate bstrRuleDescription\n"); goto Cleanup; }
	if (NULL == bstrRuleGroup) { printf("Failed to allocate bstrRuleGroup\n"); goto Cleanup; }
	if (NULL == bstrRuleLPorts) { printf("Failed to allocate bstrRuleLPorts\n"); goto Cleanup; }

	// Initialize COM.
	hrComInit = CoInitializeEx(
		0,
		COINIT_APARTMENTTHREADED
	);

	// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
	if (hrComInit != RPC_E_CHANGED_MODE)
	{
		if (FAILED(hrComInit))
		{
			printf("CoInitializeEx failed: 0x%08lx\n", hrComInit);
			goto Cleanup;
		}
	}

	// Retrieve INetFwPolicy2
	hr = WFCOMInitialize(&pNetFwPolicy2);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	// 检查是否开启了防火墙
	res = GetCurrentFirewallState(pNetFwPolicy2);
	if (3 == res) {
		goto Cleanup;
	}
	else if (4 == res) {
		printf("[*] Add Firewall Exception Rule For Port %d.\n", P);
	}

	// Retrieve INetFwRules  - https://docs.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_rules
	hr = pNetFwPolicy2->get_Rules(&pFwRules);
	if (FAILED(hr))
	{
		printf("get_Rules failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// 先清理掉之前开放的规则
	hr = pFwRules->Remove(bstrRuleName);
	if (FAILED(hr))
	{
		printf("[-] Firewall Rule Remove failed: 0x%08lx\n", hr);
		goto Cleanup;
	}
	else {
		printf("[+] Firewall Rule Remove succeeded.\n");
	}

	// Create a new Firewall Rule object.
	hr = CoCreateInstance(
		__uuidof(NetFwRule),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&pFwRule);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// INetFwRule接口
	// Populate the Firewall Rule object  https://docs.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule
	hr = pFwRule->put_Name(bstrRuleName);
	if (FAILED(hr))
	{
		printf("put_Name failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Populate the Firewall Rule Description
	hr = pFwRule->put_Description(bstrRuleDescription);
	if (FAILED(hr))
	{
		printf("put_Description failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Populate the Firewall Rule Protocol
	hr = pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
	if (FAILED(hr))
	{
		printf("put_Protocol failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = pFwRule->put_Enabled(VARIANT_TRUE);
	if (FAILED(hr))
	{
		printf("put_Enabled failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// pFwRule->put_Profiles(CurrentProfilesBitMask);
	hr = pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);  // 对所有配置文件生效
	if (FAILED(hr))
	{
		printf("put_Profiles failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Populate the Firewall Rule Group
	hr = pFwRule->put_Grouping(bstrRuleGroup);     // 指定单个规则所属的组。
	if (FAILED(hr))
	{
		printf("put_Grouping failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
	if (FAILED(hr))
	{
		printf("put_Protocol failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Populate the Firewall Rule Local Ports
	hr = pFwRule->put_LocalPorts(bstrRuleLPorts);  // 指定此规则的本地端口列表。
	if (FAILED(hr))
	{
		printf("put_LocalPorts failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = pFwRule->put_Action(NET_FW_ACTION_ALLOW);
	if (FAILED(hr))
	{
		printf("put_Action failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Add the Firewall Rule
	hr = pFwRules->Add(pFwRule);
	if (FAILED(hr))
	{
		printf("[-] Firewall Rule Add failed: 0x%08lx\n", hr);
		goto Cleanup;
	}
	else {
		printf("[+] Firewall Rule Add succeeded.\n");
	}
	Sleep(1000);
	// 检查我们的组是否启用成功
	IsRuleGroupEnabled(pNetFwPolicy2, RuleGroup);
	return TRUE;

Cleanup:

	// Free BSTR's
	SysFreeString(bstrRuleName);
	SysFreeString(bstrRuleDescription);
	SysFreeString(bstrRuleGroup);
	SysFreeString(bstrRuleLPorts);

	// Release the INetFwRule object
	if (pFwRule != NULL)
	{
		pFwRule->Release();
	}

	// Release the INetFwRules object
	if (pFwRules != NULL)
	{
		pFwRules->Release();
	}

	// Release the INetFwPolicy2 object
	if (pNetFwPolicy2 != NULL)
	{
		pNetFwPolicy2->Release();
	}

	// Uninitialize COM.
	if (SUCCEEDED(hrComInit))
	{
		CoUninitialize();
	}

	return FALSE;
}

// Instantiate INetFwPolicy2
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	HRESULT hr = S_OK;

	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2),
		(void**)ppNetFwPolicy2);

	if (FAILED(hr))
	{
		printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

Cleanup:
	return hr;
}

// https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcptable
//  获取Tcp端口状态
BOOL GetTcpPortState(ULONG nPort)
{
	MIB_TCPTABLE TcpTable[200];
	DWORD nSize = sizeof(TcpTable);
	if (NO_ERROR == GetTcpTable(&TcpTable[0], &nSize, TRUE))
	{
		DWORD nCount = TcpTable[0].dwNumEntries;
		if (nCount > 0)
		{
			for (DWORD i = 0; i < nCount; i++)
			{
				MIB_TCPROW TcpRow = TcpTable[0].table[i];
				DWORD temp1 = TcpRow.dwLocalPort;
				int temp2 = temp1 / 256 + (temp1 % 256) * 256;
				if (temp2 == nPort)
				{
					return TRUE;
				}
			}
		}
		return FALSE;
	}
	else {
		printf("[-] GetTcpTable\n");
	}
	return FALSE;
}

//获取Udp端口状态
BOOL GetUdpPortState(ULONG nPort)
{
	MIB_UDPTABLE UdpTable[100];
	DWORD nSize = sizeof(UdpTable);
	if (NO_ERROR == GetUdpTable(&UdpTable[0], &nSize, TRUE))
	{
		DWORD nCount = UdpTable[0].dwNumEntries;
		if (nCount > 0)
		{
			for (DWORD i = 0; i < nCount; i++)
			{
				MIB_UDPROW TcpRow = UdpTable[0].table[i];
				DWORD temp1 = TcpRow.dwLocalPort;
				int temp2 = temp1 / 256 + (temp1 % 256) * 256;
				if (temp2 == nPort)
				{
					return TRUE;
				}
			}
		}
		return FALSE;
	}
	return FALSE;
}


//封装字符型注册表操作
BOOL setStringValueToReg(HKEY hRoot, const char* szSubKey, const char* szValueName, const char* szValue)
{
	HKEY hKey;
	long lRet;
	if (lRet = RegCreateKeyEx(hRoot, szSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL)) return false;
	if (lRet = RegSetValueEx(hKey, szValueName, 0, REG_SZ, (BYTE*)szValue, strlen(szValue))) return false;
	RegCloseKey(hKey);
	RegCloseKey(hRoot);
	return true;
}

//封装数值型（DWORD）注册表操作
BOOL setDWORDValueToReg(HKEY hRoot, const char* szSubKey, const char* szValueName, DWORD szValue)
{
	HKEY hKey;
	long lRet;
	if (lRet = RegCreateKeyEx(hRoot, szSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL)) return false;
	if (lRet = RegSetValueEx(hKey, szValueName, 0, REG_DWORD, (BYTE*)&szValue, sizeof(DWORD))) return false;
	RegCloseKey(hKey);
	RegCloseKey(hRoot);
	return true;
}

//封装数值型（DWORD）注册表查询
DWORD getDWORDValueToReg(HKEY hRoot, const char* szSubKey, const char* szValueName)
{
	DWORD GetValue = 0;
	DWORD dataSize = sizeof(GetValue);
	HKEY hKey = NULL;
	DWORD lResult = 0;
	lResult = RegOpenKeyExA(hRoot, szSubKey, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		if (lResult == ERROR_FILE_NOT_FOUND) {
			printf("[-] Key %s not found.\n", szSubKey);
		}
		else {
			printf("[-] RegOpenKeyExA failed (%d)\n", lResult);
		}
		return FALSE;
	}

	lResult = RegGetValueA(hKey, NULL, szValueName, RRF_RT_REG_DWORD, NULL, &GetValue, &dataSize);
	switch (lResult) {
	case ERROR_SUCCESS: {
		printf("[*] RegGet %s is %d\n", szValueName, GetValue);
		break;
	}
	case ERROR_MORE_DATA: {
		printf("[-] %s 缓冲区太小\n", szValueName);
		break;
	}
	case ERROR_FILE_NOT_FOUND: {
		printf("[-] %s 注册表值不存在\n", szValueName);
		break;
	}
	default:
	{
		printf("[-] RegQueryValueEx failed (%d)\n", lResult);
		break;
	}
	}
	RegCloseKey(hKey);
	return GetValue;
}

/// <summary>
/// 启用RDP
/// </summary>
/// <param name="PORT"></param>
/// <param name="EnableSta"></param>
/// <param name="ChangeBind"></param>
/// <param name="WIN2000"></param>
/// <returns></returns>
BOOL SetReg(DWORD PORT, BOOL EnableSta = FALSE, BOOL ChangeBind = FALSE, BOOL WIN2000 = FALSE)
{
	DWORD GetPort = 0;
	DWORD dataSize = sizeof(GetPort);

	// 查询端口
	GetPort = getDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "PortNumber");

	if (GetPort == PORT) {
		printf("[!] New Port is equal to Old Port\n");
	}

	//是否改变端口
	if (ChangeBind) {
		// 修改RDP监听端口，先关闭RDP功能 -  WIN7 - WIN 2008 - WIN10
		// 指定启用远程桌面连接。
		// true  指定拒绝远程桌面连接。 这是默认值。
		// false 指定启用远程桌面连接。
		// set fDenyTSConnections = 1 拒绝连接
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections", 0x00000001)) {
			printf("[*] Set fDenyTSConnections = 1\n");
		}
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "fEnableWinStation", 0x00000000)) {
			printf("[*] Set fEnableWinStation = 0\n");
		}

		int count = 0;
		printf("[*] Wait for port %d release...\n", GetPort);
		do {
			Sleep(500);
			count += 1;
			if (count > 40) {
				printf("[-] Port release faied.\n");
				break;
			}
		} while (GetTcpPortState(GetPort));
		if (count > 40) {
			return FALSE;
		}
		printf("[+] RDP Port %d Release succeeded!\n\n", GetPort);

		//设置端口 WIN7 - WIN 2008 - WIN10
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "PortNumber", PORT)) {
			printf("[+] Set PortNumber = %d\n", PORT);
		}

		// 端口设置完成后 启用远程桌面连接
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections", 0x00000000)) {
			printf("[*] Set fDenyTSConnections = 0\n");
		}
		if (setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "fEnableWinStation", 0x00000001)) {
			printf("[*] Set fEnableWinStation = 1\n");
		}
		count = 0;
		printf("[*] Wait for port %d Bind...\n", PORT);
		do {
			Sleep(500);
			count += 1;
			if (count > 60) {
				printf("[-] Port Bind faied.\n");
				break;
			}
		} while (!GetTcpPortState(PORT));
		if (count > 60) {
			return FALSE;
		}
		else {
			printf("[+] RDP Change Port succeeded!\n");
		}
	}
	// 仅设置注册表启用RDP
	else if (EnableSta) {
		if (!setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections", 0x00000000) || !setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "fEnableWinStation", 0x00000001)) {
			printf("[-] Set fDenyTSConnections Or fEnableWinStation faied.\n");
			return FALSE;
		}
		else {
			printf("[+] Set fDenyTSConnections And fEnableWinStation succeeded!\n");
		}
	}
	else if (WIN2000) {
		// 低版本、非主流版本等
		// 修改端口- WIN2008-NOT-没用到的注册表项，功能待测试。
	   // setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp", "PortNumber", PORT);

	   // Set PortNumber
	   // 修改端口- 这个配置没找到对应的主机版本
	   // setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RDPTcp", "PortNumber", PORT);

	   /*win2000*/
	   //重新初始化脱机文件缓存和数据库
		if (!setStringValueToReg(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\netcache", "Enabled", "0")) {
			printf("[-] Set Enabled faied \n ");
		}

		//ShutdownWithoutLogon，1：用户可无需登录关闭系统，0 登录界面不显示关闭按钮
		if (!setStringValueToReg(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "ShutdownWithoutLogon", "0")) {
			printf("[-] Set ShutdownWithoutLogon faied \n ");
		}

		//启用管理员连接 
		if (!setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "EnableAdminTSRemote", 0x00000001)) {
			printf("[-] Set EnableAdminTSRemote faied \n ");
		}

		//启用服务 ,在启动模式下设置终端服务
		if (!setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "TSEnabled", 0x00000001)) {
			printf("[-] Set TSEnabled faied \n ");
		};

		if (!setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\TermDD", "Start", 0x00000002)) {
			printf("[-] Set Start faied \n ");
		}

		if (!setDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\TermService", "Start", 0x00000002)) {
			printf("[-] Set TermService-Start faied\n ");
		}
		if (!setStringValueToReg(HKEY_USERS, ".DEFAULT\\Keyboard Layout\\Toggle", "Hotkey", "2")) {
			printf("[-] Set Toggle-Hotkey faied\n ");
		}
		printf("[*] All Reg Value Set Done.\n");
	}
	return TRUE;
}

BOOL GetWinVersion() {
	// NTSTATUS 也是Long类型。 WINAPI* ,  __stdcall* 都是来声明函数指针的，指向后面这个结构体指针
		// static NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);

		// 声明一个__stdcall函数指针, LP - OSVERSIONINFOEXW 长整型指针 // Nt**、Zw**和Rtl** 开头表示未公开 
	typedef LONG(__stdcall* lpRtlGetVersion)(LPOSVERSIONINFOEXW);

	BOOL Sup = FALSE;

	lpRtlGetVersion RtlGetVersion = NULL;
	OSVERSIONINFOEXW OSInfo = { sizeof(OSVERSIONINFOEXW), 0, 0, 0, 0,{ 0 } };
	LPCTSTR lpszMajorName = NULL;
	DWORD    dwPlatformId = 0;
	DWORD    dwMajorVersion = 0;
	DWORD    dwMinorVersion = 0;
	DWORD    dwBuildNumber = 0;

	BYTE  wProductType = NULL;
	WCHAR* szCSDVersion = NULL;
	WORD wServicePackMajor = NULL;
	WORD wServicePackMinor = NULL;

	// Get ntdll.dll
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	if (!ntdll)
	{
		return FALSE;
	}
	//  *(FARPROC*)&RtlGetVersion = GetProcAddress(hNtDll, "RtlGetVersion");

	RtlGetVersion = (lpRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		return FALSE;
	}

	NTSTATUS ntStatus = RtlGetVersion(&OSInfo);
	if (ntStatus != 0) {
		return FALSE;
	}

	dwPlatformId = OSInfo.dwPlatformId;      // 系统支持的平台
	dwMajorVersion = OSInfo.dwMajorVersion;  // 主要版本
	dwMinorVersion = OSInfo.dwMinorVersion;  // 次要版本
	dwBuildNumber = OSInfo.dwBuildNumber;    // 构建版本号

	 // 标识系统类型 https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoa
	wProductType = OSInfo.wProductType;

	szCSDVersion = OSInfo.szCSDVersion;      // 系统补丁包的名称
	wServicePackMajor = OSInfo.wServicePackMajor; // 系统补丁包的主版本
	wServicePackMinor = OSInfo.wServicePackMinor; // 系统补丁包的主版本

	switch (dwPlatformId)
	{
	case VER_PLATFORM_WIN32_NT:
		switch (dwMajorVersion)
		{

		case 5:
			if (dwMinorVersion == 0) {
				lpszMajorName = (VER_NT_WORKSTATION == wProductType) ? "2000" : "2000 Server";
			}
			else {
				if (dwMinorVersion == 1) {
					lpszMajorName = "XP";
				}
				else {
					if (dwMinorVersion == 2) {
						lpszMajorName = (VER_NT_WORKSTATION == wProductType) ? "XP x64" : "Server 2003";
					}
				}
			}
			break;
		case 6:
			if (dwMinorVersion == 0) {
				lpszMajorName = (VER_NT_WORKSTATION == wProductType) ? "Vista" : "Server 2008";
			}
			else
				if (dwMinorVersion == 1) {
					lpszMajorName = (VER_NT_WORKSTATION == wProductType) ? "7" : "Server 2008 R2";
				}
				else
					if (dwMinorVersion == 2) {
						lpszMajorName = (VER_NT_WORKSTATION == wProductType) ? "8" : "Server 2012";
					}
					else
						if (dwMinorVersion == 3)
						{
							lpszMajorName = (VER_NT_WORKSTATION == wProductType) ? "8.1" : "Server 2012 R2";
						}
			break;
		case 10:
			if (dwMinorVersion == 0) {
				lpszMajorName = (VER_NT_WORKSTATION == wProductType) ? "10" : "Server 2016"; \
			}
			break;
		default:
			break;
		}
		printf("[+] Version:");
		if (!lpszMajorName)
		{
			if (wServicePackMajor)
				printf("Windows %u.%u.%u, SP %u", dwMajorVersion, dwMinorVersion, dwBuildNumber, wServicePackMajor);
			else
				printf("Windows %u.%u.%u", dwMajorVersion, dwMinorVersion, dwBuildNumber);
		}
		else
		{
			if (wServicePackMajor)
				printf("Windows %s [%u.%u.%u] - SP %u", lpszMajorName, dwMajorVersion, dwMinorVersion, dwBuildNumber, wServicePackMajor);
			else
				printf("Windows %s [%u.%u.%u]", lpszMajorName, dwMajorVersion, dwMinorVersion, dwBuildNumber);
		}
		if (szCSDVersion[0])
		{
			printf("(%ls)", szCSDVersion);
		}
		break;

	default:
	{
		printf("<platform id %u>", dwPlatformId);
	}
	break;
	}
	printf("\n");

	// 检查版本类型，然后排除不支持的系统 :)
	const char* edition = "";
	DWORD ed;
	if (GetProductInfo(dwMajorVersion, dwMinorVersion, wServicePackMajor, wServicePackMinor, &ed))
	{
		printf("[*] PRODUCT_PROFESSIONAL: %d \n", ed);
		switch (ed)
		{
		case PRODUCT_ULTIMATE:
		{
			Sup = TRUE;
			edition = "Ultimate"; //旗舰版
			break;
		}
		case PRODUCT_BUSINESS:
		{
			Sup = TRUE;
			edition = "Business";
			break;
		}
		case PRODUCT_BUSINESS_N:
		{
			Sup = TRUE;
			edition = "Business N";
			break;
		}
		case PRODUCT_PROFESSIONAL:
		{
			Sup = TRUE;
			edition = "Windows 10 Pro";
			break;
		}
		case PRODUCT_PRO_WORKSTATION:
		{
			Sup = TRUE;
			edition = "Pro for Workstations";
			break;
		}
		case PRODUCT_PRO_WORKSTATION_N:
		{
			Sup = TRUE;
			edition = "Windows 10 Pro for Workstations N";
			break;
		}

		case PRODUCT_PROFESSIONAL_E:
		{
			edition = "Not supported";
			break;
		}
		case PRODUCT_PROFESSIONAL_N:
		{
			Sup = TRUE;
			edition = "Windows 10 Pro N";
			break;
		}
		case PRODUCT_UNDEFINED:
		{
			edition = "An unknown product";
			break;
		}
		case PRODUCT_EDUCATION:
		{
			Sup = TRUE;
			edition = "Windows 10 Education";
			break;
		}

		case PRODUCT_EDUCATION_N: {
			Sup = TRUE;
			edition = "Windows 10 Education N";
			break;
		}
		case PRODUCT_ENTERPRISE:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise";
			break;
		}
		case PRODUCT_ENTERPRISE_E:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise E";
			break;
		}
		case PRODUCT_ENTERPRISE_EVALUATION:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise Evaluation";
			break;
		}
		case PRODUCT_ENTERPRISE_N:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise N";
			break;
		}
		case PRODUCT_ENTERPRISE_N_EVALUATION:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise N Evaluation";
			break;
		}
		case PRODUCT_ENTERPRISE_S:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise 2015 LTSB";
			break;
		}
		case PRODUCT_ENTERPRISE_S_EVALUATION:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise 2015 LTSB Evaluation";
			break;
		}
		case PRODUCT_ENTERPRISE_S_N:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise 2015 LTSB N";
			break;
		}
		case PRODUCT_ENTERPRISE_S_N_EVALUATION:
		{
			Sup = TRUE;
			edition = "Windows 10 Enterprise 2015 LTSB N Evaluation";
			break;
		}
		case PRODUCT_HOME_BASIC:
		{
			edition = "Home Basic";
			break;
		}
		case PRODUCT_HOME_BASIC_E:
		{
			edition = "Not supported";
			break;
		}
		case PRODUCT_HOME_BASIC_N:
		{
			edition = "Home Basic N";
			break;
		}
		case PRODUCT_HOME_PREMIUM:
		{
			edition = "Home Premium";
			break;
		}
		case PRODUCT_HOME_PREMIUM_E:
		{
			edition = "Not supported";
			break;
		}

		case PRODUCT_CORE:
		{
			edition = "Windows 10 Home";
			break;
		}
		case PRODUCT_CORE_COUNTRYSPECIFIC:
		{
			edition = "Windows 10 Home China";
			break;
		}
		case PRODUCT_CORE_N:
		{
			edition = "Windows 10 Home N";
			break;
		}
		case PRODUCT_CORE_SINGLELANGUAGE:
		{
			edition = "Windows 10 Home Single Language";
			break;
		}
		default:
			edition = "Unknown";
			break;
		}
		printf("[+] Found edition: %s\n", edition);
	}
	return Sup;
}

/// <summary>
/// 检查服务状态
/// </summary>
/// <returns></returns>
BOOL CheckService() {
	SC_HANDLE shSCManager = NULL, shService = NULL;
	SERVICE_STATUS_PROCESS stat;
	DWORD dwSize = 0;
	DWORD dwLpqscSize = 0;
	LPQUERY_SERVICE_CONFIGA lpServiceConfig = NULL;
	DWORD needed = 0;
	BOOL ret = TRUE;
	shSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	shService = OpenService(shSCManager, "TermService", SERVICE_ALL_ACCESS);
	if (!shService)
	{
		printf("[-] OpenService Failed \n");
		goto clean;
	}

	ret = QueryServiceStatusEx(shService, SC_STATUS_PROCESS_INFO,
		(BYTE*)&stat, sizeof stat, &needed);
	if (ret == 0) {
		printf("[-] QueryServiceStatusEx failed\n");
		goto clean;
	}

	if (stat.dwCurrentState == SERVICE_RUNNING) {
		printf("[+] TermService is running\n");
	}
	else {
		// 服务停止失败等情况
		if (stat.dwCurrentState != SERVICE_STOPPED) {
			printf("[-] TermService failed,CurrentState: %d \n  ", stat.dwCurrentState);
		}
		else { printf("[-] TermService is NOT running\n"); }
		return FALSE;
	}
	return TRUE;

clean:
	if (NULL != shSCManager)
		CloseServiceHandle(shSCManager);
	if (NULL != shService)
		CloseServiceHandle(shService);
	return FALSE;
}

/// <summary>
/// 启动服务
/// </summary>
/// <returns></returns>
BOOL NetStartServices() {
	SC_HANDLE shSCManager = NULL, shService = NULL;
	SERVICE_STATUS_PROCESS stat;
	DWORD dwSize = 0;
	DWORD dwLpqscSize = 0;
	LPQUERY_SERVICE_CONFIGA lpServiceConfig = NULL;
	DWORD needed = 0;
	BOOL ret = TRUE;
	shSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	shService = OpenService(shSCManager, "TermService", SERVICE_ALL_ACCESS);
	if (!shService)
	{
		printf("[-] OpenService Failed \n");
		goto clean;
	}

	ret = QueryServiceStatusEx(shService, SC_STATUS_PROCESS_INFO,
		(BYTE*)&stat, sizeof stat, &needed);
	if (ret == 0) {
		printf("QueryServiceStatusEx failed\n");
		goto clean;
	}
	if (stat.dwCurrentState == SERVICE_RUNNING) {
		printf("[+] TermService is running\n");
	}
	else {
		// 服务停止失败等情况
		if (stat.dwCurrentState != SERVICE_STOPPED) {
			printf("[-] TermService failed,CurrentState: %d \n  ", stat.dwCurrentState);
			return FALSE;
		}
		printf("[-] TermService is NOT running\n");

		// 查询服务启动类型
		if (!QueryServiceConfigA(shService, NULL, 0, &dwSize)) {
			if (dwSize) {
				// This part is not critical error will not stop the program
				dwLpqscSize = dwSize;
				printf("[*] LPQUERY_SERVICE_CONFIGA need 0x%08x bytes\n", dwLpqscSize);
				lpServiceConfig = (LPQUERY_SERVICE_CONFIGA)GlobalAlloc(GPTR, dwSize);
				if (lpServiceConfig == NULL) {
					printf("[-] Out of memory");
					return FALSE;
				}
				if (QueryServiceConfigA(shService, lpServiceConfig, dwLpqscSize, &dwSize)) {
					printf("[*] Start type: %d \n", lpServiceConfig->dwStartType);
					if (lpServiceConfig->dwStartType == SERVICE_DISABLED) {
						//设置服务为自启动
						printf("[*] Try to ChangeServiceConfig\n");
						if (ChangeServiceConfig(shService, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
							printf("[+] ChangeServiceConfig succeeded\n");
							// Waiting for configuration to take effect
							Sleep(500);
							if (StartService(shService, 0, NULL)) {
								printf("[+] Start TermService succeeded\n");
							}
							else {
								printf("[-] Start TermService failed  (%d) \n", GetLastError());
								goto clean;
							}
						}
						else {
							printf("[-] ChangeServiceConfig failed  (%d) \n", GetLastError());
							goto clean;
						}
					}
					else {
						//启动服务
						printf("[*] Try to Start TermService\n");
						if (StartService(shService, 0, NULL)) {
							printf("[+] Start TermService succeeded\n");
						}
						else
						{
							printf("[-] Start TermService failed  (%d) \n", GetLastError());
							goto clean;
						}
					}
				}
				else { printf("[-] QueryServiceConfigA failed\n"); goto clean; }
			}
		}
	}

	if (NULL != shSCManager)
		CloseServiceHandle(shSCManager);
	if (NULL != shService)
		CloseServiceHandle(shService);
	return TRUE;
clean:
	if (NULL != shSCManager)
		CloseServiceHandle(shSCManager);
	if (NULL != shService)
		CloseServiceHandle(shService);
	return FALSE;
}


/// <summary>
/// 检查一下注册表里有没有 TermService 服务
/// </summary>
/// <returns></returns>
BOOL CheckTermServiceReg() {
	HKEY hKey = NULL;
	if (ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\TermService", 0, KEY_ALL_ACCESS, &hKey)) {
		printf("[-] RegOpenKeyExA failed\n");
		return FALSE;
	}
	return TRUE;
}


/// <summary>
/// 检查当前会话是否已经在远程会话中
/// https://docs.microsoft.com/zh-cn/windows/win32/termserv/detecting-the-terminal-services-environment
/// </summary>
/// <returns></returns>
BOOL IsCurrentSessionRemoteable()
{
	BOOL fIsRemoteable = FALSE;

	if (GetSystemMetrics(SM_REMOTESESSION))
	{
		fIsRemoteable = TRUE;
	}
	else
	{
		HKEY hRegKey = NULL;
		LONG lResult;

		lResult = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			TERMINAL_SERVER_KEY,
			0, // ulOptions
			KEY_READ,
			&hRegKey
		);

		if (lResult == ERROR_SUCCESS)
		{
			DWORD dwGlassSessionId;
			DWORD cbGlassSessionId = sizeof(dwGlassSessionId);
			DWORD dwType;

			lResult = RegQueryValueEx(
				hRegKey,
				GLASS_SESSION_ID,
				NULL, // lpReserved
				&dwType,
				(BYTE*)&dwGlassSessionId,
				&cbGlassSessionId
			);

			if (lResult == ERROR_SUCCESS)
			{
				DWORD dwCurrentSessionId;

				if (ProcessIdToSessionId(GetCurrentProcessId(), &dwCurrentSessionId))
				{
					fIsRemoteable = (dwCurrentSessionId != dwGlassSessionId);
				}
			}
		}

		if (hRegKey)
		{
			RegCloseKey(hRegKey);
		}
	}

	return fIsRemoteable;
}


/// <summary>
/// 检查系统版本信息和RDP的注册表、服务设置、防火墙 情况
/// </summary>
/// <returns></returns>
BOOL RdpInfoScan(BOOL IsOk = FALSE) {
	printf("[*] System information Scan...\n");
	if (IsCurrentSessionRemoteable()) {
		printf("[!] Your are in RDP Session!\n");
	}

	//检查是不是服务器版, 该函数支持 >= win2008 ;
	if (IsWindowsServer()) {
		printf("[*] Is Windows Server\n");
	}
	else {
		// 不是服务器就检查是否是支持RDP的版本
		if (GetWinVersion()) {
			printf("[+] Your OS edition support RDP.\n");
		}
		else {
			// 不支持
			printf("[-] Your OS edition does not support RDP.\n");
			return FALSE;
		}
	}

	// 检查是否具有管理员权限,因为操作注册表需要管理员权限
	if (IsUserAnAdmin()) {
		printf("[+] Success: Administrative permissions confirmed\n\n");
	}
	else {
		printf("[-] Failure: Current permissions inadequate\n");
		return FALSE;
	}

	//检查注册表中是否存在 TermService 服务
	if (!CheckTermServiceReg()) {
		printf("[-] Your system not install TermService\n");
		return FALSE;
	}
	else {
		printf("[+] Find TermService in registry\n");
	}

	if (!IsOk) {
		//检查设置的端口
		DWORD DCheckPort = getDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "PortNumber");
	}

	if (!IsOk) {
		//检查注册表中fDenyTSConnections的状态
		DWORD DCheckfDenyTSConnections = getDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections");
		if (0 == DCheckfDenyTSConnections) {
			printf("[+] TermService Connections is enable in key fDenyTSConnections \n");
		}
		else {
			printf("[-] TermService Connections is disable in key fDenyTSConnections\n");
		}
	}

	if (!IsOk) {
		//检查注册表中fEnableWinStation的状态
		DWORD DCheckfEnableWinStation = getDWORDValueToReg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "fEnableWinStation");
		if (1 == DCheckfEnableWinStation) {
			printf("[+] TermService Connections is enable in key fEnableWinStation \n");
		}
		else {
			printf("[-] TermService Connections is disable in key fEnableWinStation\n");
		}
	}
	//检查防火墙开放情况
	if (!IsOk) {
		CheckFireWallState();
	}

	//检查服务是否正在运行
	if (!CheckService()) {
		if (IsOk) {
			printf("[-] The Service is NOT running\n");
		}
		else {
			printf("[-] The Service is NOT running. You can try to start it later\n");
			return FALSE;
		}
	}
	printf("[+] Your system support for rdp\n\n");
	return TRUE;
}


int main(int argc, char* argv[])
{
	clock_t start, end;
	start = clock();
	if (argc == 1) {
		printf("[*] ===========================================================\n");
		printf(" %s\n", argv[0]);
		printf(" \t -- this help\n");
		printf(" %s any\n", argv[0]);
		printf(" \t -- Output system version, registry value, service status and firewall status\n");
		printf(" %s port 1\n", argv[0]);
		printf(" \t -- Only set fDenyTSConnections=0 And fEnableWinStation=1(Ignore port set) \n");
		printf(" %s port 2\n", argv[0]);
		printf(" \t -- Modify the registry, start services, and set up firewalls\n");
		printf(" %s port 3\n", argv[0]);
		printf(" \t -- Set firewall on the specified port(Allow In,It will be remove same rule)\n");
		printf(" %s port 4\n", argv[0]);
		printf(" \t -- Try to start service(Ignore port input)\n");
		printf(" %s port 5\n", argv[0]);
		printf(" \t -- Try to Modify the registry for enable RDP on a lower version system(Ignore port input)\n");
		printf("[*] ===========================================================\n\n");
	}
	else if (argc == 2) {
		RdpInfoScan();
	}
	else if (argc == 3) {
		DWORD PORT = 3389;

		//1: 启用注册表，2:修改端口并启用RDP、开放防火墙 3.仅设置防火墙 4.仅尝试启动服务 5. 尝试在WIN2000中设置注册表启用RDP.
		DWORD Action = 1;
		// 获取输入的端口，并转为int型
		PORT = atoi(argv[1]);
		Action = atoi(argv[2]);

		// 如果转换失败
		if (PORT == 0 || Action == 0) {
			printf("[-] atoi error, Please check your input( enrdp.exe 3389 action(int) ).\n");
		}
		else {
			//如果输入的端口不在端口范围内
			if (PORT < 1 || PORT > 65535) {
				printf("[-] Please check your input( 1-65535 ).\n");
			}
			else {
				//1.仅启用注册表设置 :)
				if (Action == 1) {
					printf("[*] Only Set Reg To Enable RDP,Ignore port set\n");
					SetReg(PORT, TRUE);
				}
				else if (Action == 2) {
					// 配置检查
					if (RdpInfoScan(TRUE)) {
						//修改端口、启用RDP、开放防火墙
						// 检查端口是否被占用 (通过获取本机端口状态判断)
						if (GetTcpPortState(PORT) || GetUdpPortState(PORT)) {
							printf("[-] The port is occupied, please replace the port.\n");
						}
						else {
							printf("[*] The port is not occupied\n");
							printf("[*] Make sure TermService runing...\n");
							if (NetStartServices()) {
								printf("[*] Change Port...\n");
								if (SetReg(PORT, FALSE, TRUE)) {
									printf("[*] SetFireWall...\n");
									if (SetFireWall(PORT))
									{
										printf("[+] Successful\n");
									}
								}
							}
						}
					}
					else {
						printf("[-] Configuration check failed\n");
					}
				}
				else if (Action == 3) {
					if (SetFireWall(PORT))
					{
						printf("[+] Successful\n");
					}
				}
				else if (Action == 4) {
					if (NetStartServices()) {
						printf("[+] Successful\n");
					}
				}
				else if (Action == 5) {
					if (SetReg(PORT, FALSE, FALSE, TRUE)) {
						printf("[+] Successful\n");
					}
				}
				else {
					return TRUE;
				}
			}
		}
	}
	else {
		return TRUE;
	}
	end = clock();
	printf("\n[*] Done. Time used: %lf seconds.\n", (double)((double)end - (double)start) / CLOCKS_PER_SEC);
	return TRUE;
}