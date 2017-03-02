#include "StdAfx.h"
#include ".\gpopwd.h"
#include <stdio.h>
#include <lm.h>
#define   INITGUID 
#include <Guiddef.h>
#include <Gpedit.h>
#include <Userenv.h>
#include <Wuapi.h>
#include <afx.h>
#include <Wincrypt.h>
#include <windows.h>
#include <afxstr.h>
#include <winbase.h>
#include "..\..\TestContainer\TestContainer\SMBiosStructs.h"
#include <iostream>
#include <fstream>
//#include <Usbdlib.h>
//#include <Usbioctl.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib,"Wuguid.lib")
//#pragma comment(lib,".\\lib\\setupapi.lib")
#pragma comment(lib,".\\lib\\hid.lib")

#ifdef _WIN64
#pragma comment(lib,".\\libx64\\setupapi.lib")
#else
#pragma comment(lib,".\\lib\\setupapi.lib")
#endif
//#pragma comment(lib, "samlib.lib")

extern "C" 
{  
#include "setupapi.h" 
#include "hidsdi.h" 
#include <iosfwd>
}

#define MAX_VALUE_LENGTH 1024

static std::wstring sMemoryTypeInfoCollection;

/////////////////////////////////////////////////////////////////////////////
// CSMBIOSViewerDlg message handlers
void EnumTablesCallback(DWORD dwParam, EnumTableStruct* pstEnumTableStruct)//���=17�ľͽ���
{
	//int n = pstEnumTableStruct->dwTableType;
	//CString str;
	//str.Format(_T("type:%d"),n);
	//MessageBox(NULL,str.GetBuffer(),_T("wode"),MB_OK);
	if(17 == pstEnumTableStruct->dwTableType)
	{
		DWORD dwTableSize;
		//SMBios_TypeBase* pstTypeBase = (SMBios_TypeBase*)m_oSMBIOSData.GetTableByIndex(pstEnumTableStruct->dwIndex,dwTableSize);
		int nStart = pstEnumTableStruct->dwOffsetOfTableFromBeginning;
		SMBiosData* pSMBIOSDATA = (SMBiosData*)dwParam;
		BYTE* pData = pSMBIOSDATA->GetRawData();
		BYTE bResult = pData[nStart + 18];
		std::wstring sType;
		switch(bResult)
		{
		case 1:
			sType = _T("Other");
			break;
		case 2:
			if(SMBiosData::bVersionAfterTwoPointSix)
			{
				sType = _T("Unkonw");
			}
			else
			{
				sType = _T("DDR3");
			}
			
			break;
		case 3:
			sType = _T("DRAM");
			break;
		case 4:
			sType = _T("EDRAM");
			break;
		case 5:
			sType = _T("VRAM");
			break;
		case 6:
			sType = _T("SRAM");
			break;
		case 7:
			sType = _T("RAM");
			break;
		case 8:
			sType = _T("ROM");
			break;
		case 9:
			sType = _T("FLASH");
			break;
		case 10:
			sType = _T("EEPROM");
			break;
		case 11:
			sType = _T("FEPROM");
			break;
		case 12:
			sType = _T("EPROM");
			break;
		case 13:
			sType = _T("CDRAM");
			break;
		case 14:
			sType = _T("3DRAM");
			break;
		case 15:
			sType = _T("SDRAM");
			break;
		case 16:
			sType = _T("SGRAM");
			break;
		case 17:
			sType = _T("RDRAM");
			break;
		case 18:
			sType = _T("DDR");
			break;
		case 19:
			sType = _T("DDR2");
			break;
		case 20:
			sType = _T("DDR2 FB-DIMM");
			break;
		case 21:
			sType = _T("Reserved");
			break;
		case 22:
			sType = _T("Reserved");
			break;
		case 23:
			sType = _T("Reserved");
			break;
		case 24:
			sType = _T("DDR3");
			break;
		case 25:
			sType = _T("FBD2");
			break;	
		}
		sMemoryTypeInfoCollection += sType;
		sMemoryTypeInfoCollection += _T(";");
	}
}

//private static extern NTSTATUS SamCloseHandle(IntPtr ServerHandle);//
//private static extern NTSTATUS SamFreeMemory(IntPtr Handle);//
//private static extern NTSTATUS SamOpenDomain(IntPtr ServerHandle, DOMAIN_ACCESS_MASK DesiredAccess, byte[] DomainId, out IntPtr DomainHandle);//
//private static extern NTSTATUS SamLookupDomainInSamServer(IntPtr ServerHandle, UNICODE_STRING name, out IntPtr DomainId);//
//private static extern NTSTATUS SamQueryInformationDomain(IntPtr DomainHandle, DOMAIN_INFORMATION_CLASS DomainInformationClass, out IntPtr Buffer);//
//private static extern NTSTATUS SamSetInformationDomain(IntPtr DomainHandle, DOMAIN_INFORMATION_CLASS DomainInformationClass, IntPtr Buffer);//
//private static extern NTSTATUS SamEnumerateDomainsInSamServer(IntPtr ServerHandle, ref int EnumerationContext, out IntPtr EnumerationBuffer, int PreferedMaximumLength, out int CountReturned);

CPolicyTool::CPolicyTool(void)
{

	//HMODULE hdll = ::LoadLibrary(_T("C:\\Windows\\System32\\Samlib.dll"));
	//if (hdll){
	//	_SamConnect = (pfnSamConnect)::GetProcAddress(hdll,"SamConnect");
	//	_SamEnumerateDomainsInSamServer = (pfnSamEnumerateDomainsInSamServer)::GetProcAddress(hdll,"SamEnumerateDomainsInSamServer");
	//}
}

CPolicyTool::~CPolicyTool(void)
{
}

bool CPolicyTool::QueryPasswordPolicies()
{
	bool bRet(false);

	DWORD dwLevel = 0;//����Global Password Parameters
	USER_MODALS_INFO_0 *pBuf = NULL;
	NET_API_STATUS nStatus;

	nStatus = NetUserModalsGet(NULL, //��ȡ��ǰ����
		dwLevel,
		(LPBYTE*)&pBuf);
	if (nStatus != NERR_Success)
	{
		if (pBuf != NULL)
			NetApiBufferFree(pBuf);
		return bRet;
	}

	//�鿴���������Ƿ���ȷ
	if(8 == pBuf->usrmod0_min_passwd_len && 5 == pBuf->usrmod0_password_hist_len)
	{
		bRet = true;
	}

	//��Ҫ�ͷ�ϵͳ����Ŀռ�
	if (pBuf != NULL)
		NetApiBufferFree(pBuf);

	return bRet;
}
//bool CPolicyTool::QueryPasswordPolicies()
//{
//	NTSTATUS nStatus;
//	int nCount(0);	
//	UNICODE_STRING name = {0};
//	OBJECT_ATTRIBUTES oa = {0};
//	SAM_HANDLE samhandle = 0;
//	PSAM_HANDLE pServerhandle = &samhandle;
//	nStatus = _SamConnect(/*&name*/0,/*(PSAM_HANDLE)&pInitPtr*/pServerhandle,SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN,&oa);	
//
//	SAM_ENUMERATE_HANDLE nEnumerateHandle = 0;
//	PSAM_ENUMERATE_HANDLE pEnumerateHandle = &nEnumerateHandle;
//	VOID *pIX = NULL;
//	//nStatus = _SamEnumerateDomainsInSamServer(hServerHandle, &nEnumerateHandle, &pInitP, 10,(PULONG)&nCount);
//	nStatus = _SamEnumerateDomainsInSamServer(pServerhandle,pEnumerateHandle , &pIX, 1,(PULONG)&nCount);
//	//__inout     PSAM_ENUMERATE_HANDLE EnumerationContext,
//	//__deref_out PVOID *Buffer,
//	unsigned long aaa = nStatus;
//
//	return true;
//}

bool CPolicyTool::SetPasswordPolicies()
{
	bool bRet(true);

	DWORD dwLevel = 0;//����Global Password Parameters
	USER_MODALS_INFO_0 *pBuf = NULL;
	NET_API_STATUS nStatus;

	nStatus = NetUserModalsGet(NULL, //��ȡ��ǰ����
		dwLevel,
		(LPBYTE*)&pBuf);
	if (nStatus != NERR_Success)
		bRet = false;

	//�޸����볤�Ⱥ���ʷ��¼����
	pBuf->usrmod0_min_passwd_len = 8;
	//ui.usrmod0_max_passwd_age = (86400 * 30);
	//ui.usrmod0_min_passwd_age = 0;
	//ui.usrmod0_force_logoff = TIMEQ_FOREVER; // never force logoff
	pBuf->usrmod0_password_hist_len = 5;

	nStatus = NetUserModalsSet(NULL,//�����²���
		dwLevel,
		(LPBYTE)pBuf,
		NULL);

	if (nStatus != NERR_Success)
		bRet = false;
	
	//��Ҫ�ͷ�ϵͳ����Ŀռ�
	if (pBuf != NULL)
		NetApiBufferFree(pBuf);

	return bRet;

}

bool CPolicyTool::ConfigureWindowsUpdate()
{
	 ::CoInitialize(NULL);
	HRESULT hr=S_OK;
	HKEY hGPOKey,hKey,hSubKey;
	//cocreateinstance���gpo����ָ��
	IGroupPolicyObject* pGPO = NULL;
	hr = CoCreateInstance(CLSID_GroupPolicyObject,NULL,CLSCTX_ALL,IID_IGroupPolicyObject,(LPVOID*)&pGPO);

	if(!SUCCEEDED(hr))
		//::MessageBox(NULL,L"GPO�ӿڶ����ʼ��ʧ��",L"",0);
	{
		return false;
	}
	
	//��ȡ����GPO
	if(pGPO->OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY) != S_OK){
		//::MessageBox(NULL,L"��ȡ����GPOӳ��ʧ��",L"",0);
		return false;}

	//��ȡ����
	if(pGPO->GetRegistryKey(GPO_SECTION_MACHINE,&hGPOKey) != S_OK){
		//::MessageBox(NULL,L"��ȡ����GPOӳ��ע������ʧ��",L"",0);
		return false;}

	//����ע����
	DWORD dwNoAutoUpdate(0),dwAUOptions(2),dwScheduledInstallDay(5),dwScheduledInstallTime(13),dwUseWUServer(1);
	TCHAR *szWUServer = _T("http://fssus.fs.gmcc.net");
	TCHAR *szWUStatusServer = _T("http://IntranetUpd01");

	//������������ע����
	if(ERROR_SUCCESS != RegOpenKeyEx(hGPOKey,_T("Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"),0,KEY_WRITE,&hKey)){
		if(ERROR_SUCCESS != RegCreateKeyEx(hGPOKey,_T("Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"),0,NULL,REG_OPTION_NON_VOLATILE,KEY_WRITE,NULL,&hKey,NULL)){
			return false;
		}
	}
	if(ERROR_SUCCESS != RegSetValueEx(hKey,_T("WUServer"),0,REG_SZ,(BYTE*)szWUServer,((_tcslen(szWUServer)+1)*sizeof(TCHAR)))){//���·�������ַ
		return false;
	}
	if(ERROR_SUCCESS != RegSetValueEx(hKey,_T("WUStatusServer"),0,REG_SZ,(BYTE*)szWUStatusServer,((_tcslen(szWUServer)+1)*sizeof(TCHAR)))){//ͳ�Ʒ�������ַ
		return false;
	}
	//��������AU��ע����
	if(ERROR_SUCCESS != RegOpenKeyEx(hGPOKey,_T("Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),0,KEY_WRITE,&hSubKey)){
		if(ERROR_SUCCESS != RegCreateKeyEx(hGPOKey,_T("Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),0,NULL,REG_OPTION_NON_VOLATILE,KEY_WRITE,NULL,&hSubKey,NULL)){
			return false;
		}
	}	
	////���ü�ֵ
	if(ERROR_SUCCESS != RegSetValueEx(hSubKey,_T("NoAutoUpdate"),0,REG_DWORD,(BYTE*)&dwNoAutoUpdate,sizeof(DWORD))){//�Ƿ�����Զ�����
		return false;
	}
	if(ERROR_SUCCESS != RegSetValueEx(hSubKey,_T("AUOptions"),0,REG_DWORD,(BYTE*)&dwAUOptions,sizeof(DWORD))){//�Զ�����ѡ��
		return false;
	}
	if(ERROR_SUCCESS != RegSetValueEx(hSubKey,_T("ScheduledInstallDay"),0,REG_DWORD,(BYTE*)&dwScheduledInstallDay,sizeof(DWORD))){//��������
		return false;
	}
	if(ERROR_SUCCESS != RegSetValueEx(hSubKey,_T("ScheduledInstallTime"),0,REG_DWORD,(BYTE*)&dwScheduledInstallTime,sizeof(DWORD))){//����ʱ��
		return false;
	}
	if(ERROR_SUCCESS != RegSetValueEx(hSubKey,_T("UseWUServer"),0,REG_DWORD,(BYTE*)&dwUseWUServer,sizeof(DWORD))){//�Ƿ��������÷�����
		return false;
	}

	GUID n1 = REGISTRY_EXTENSION_GUID;
	GUID n2 = {	0x0F6B957E,	0x509E,	0x11D1,{0xA7, 0xCC, 0x00, 0x00, 0xF8, 0x75, 0x71, 0xE3}};
	//GUID n2 = { 0x3d271cfc, 0x2bc6, 0x4ac2, { 0xb6, 0x33, 0x3b, 0xdf, 0xf5, 0xbd, 0xab, 0x2a } };//Ҳ����ʹ��

	if(S_OK != pGPO->Save(true,true,&n1 ,&n2))
	{
		return false;
	}

	RegCloseKey(hSubKey);
	RegCloseKey(hGPOKey);
	RegCloseKey(hKey);

	pGPO->Release();
	::CoUninitialize();
	return true;
}



bool CPolicyTool::QueryWindowsUPdate()
{
	boolean bRet(true);
	::CoInitialize(NULL);
	HRESULT hr=S_OK;
	HKEY hGPOKey,hKey,hSubKey;
	//cocreateinstance���gpo����ָ��
	IGroupPolicyObject* pGPO = NULL;
	hr = CoCreateInstance(CLSID_GroupPolicyObject,NULL,CLSCTX_ALL,IID_IGroupPolicyObject,(LPVOID*)&pGPO);

	if(!SUCCEEDED(hr))
		//::MessageBox(NULL,L"GPO�ӿڶ����ʼ��ʧ��",L"",0);
	{
		bRet =  false;
	}

	//��ȡ����GPO
	if(pGPO->OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY) != S_OK){
		//::MessageBox(NULL,L"��ȡ����GPOӳ��ʧ��",L"",0);
		bRet =  false;}

	//��ȡ����
	if(pGPO->GetRegistryKey(GPO_SECTION_MACHINE,&hGPOKey) != S_OK){
		//::MessageBox(NULL,L"��ȡ����GPOӳ��ע������ʧ��",L"",0);
		bRet =  false;}

	//��ע����
	TCHAR *szWUServer = _T("http://fssus.fs.gmcc.net");
	TCHAR *szWUStatusServer = _T("http://IntranetUpd01");
	TCHAR szCurrWUServer[MAX_VALUE_LENGTH];
	TCHAR szCurrWUStatusServer[MAX_VALUE_LENGTH];
	RtlZeroMemory(szCurrWUServer,MAX_VALUE_LENGTH);
	RtlZeroMemory(szCurrWUStatusServer,MAX_VALUE_LENGTH);

	if(ERROR_SUCCESS != RegOpenKeyEx(hGPOKey,_T("Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"),0,KEY_ALL_ACCESS,&hKey)){
		bRet =  false;
	}
	DWORD dwTmp(MAX_VALUE_LENGTH);
	if(ERROR_SUCCESS != RegQueryValueEx(hKey,_T("WUServer"),0,NULL,(BYTE*)szCurrWUServer,&dwTmp)){
		bRet =  false;
	}
	dwTmp = MAX_VALUE_LENGTH;
	if(ERROR_SUCCESS != RegQueryValueEx(hKey,_T("WUStatusServer"),0,NULL,(BYTE*)szCurrWUStatusServer,&dwTmp)){
		bRet =  false;
	}

	if(0 != _tcscmp(szCurrWUServer,szWUServer) || 0 != _tcscmp(szCurrWUStatusServer,szWUStatusServer) ){ 
		bRet =  false;
	}

	DWORD dwCurrNoAutoUpdate(0),dwCurrAUOptions(0),dwCurrScheduledInstallDay(0),dwCurrScheduledInstallTime(0),dwCurrUseWUServer(0);
	if(ERROR_SUCCESS != RegOpenKeyEx(hGPOKey,_T("Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"),0,KEY_ALL_ACCESS,&hSubKey)){
		bRet =  false;
	}	
	//��ȡ��ֵ
	dwTmp = sizeof(DWORD);
	if(ERROR_SUCCESS != RegQueryValueEx(hSubKey,_T("NoAutoUpdate"),0,NULL,(BYTE*)&dwCurrNoAutoUpdate,&dwTmp)){//�Ƿ�����Զ�����
		bRet =  false;
	}
	if(ERROR_SUCCESS != RegQueryValueEx(hSubKey,_T("AUOptions"),0,NULL,(BYTE*)&dwCurrAUOptions,&dwTmp)){//�Զ�����ѡ��
		bRet =  false;
	}
	if(ERROR_SUCCESS != RegQueryValueEx(hSubKey,_T("ScheduledInstallDay"),0,NULL,(BYTE*)&dwCurrScheduledInstallDay,&dwTmp)){//��������
		bRet =  false;
	}
	if(ERROR_SUCCESS != RegQueryValueEx(hSubKey,_T("ScheduledInstallTime"),0,NULL,(BYTE*)&dwCurrScheduledInstallTime,&dwTmp)){//����ʱ��
		bRet =  false;
	}
	if(ERROR_SUCCESS != RegQueryValueEx(hSubKey,_T("UseWUServer"),0,NULL,(BYTE*)&dwCurrUseWUServer,&dwTmp)){//�Ƿ��������÷�����
		bRet =  false;
	}
	if(0 != dwCurrNoAutoUpdate || 2 != dwCurrAUOptions || 5 != dwCurrScheduledInstallDay || 13 != dwCurrScheduledInstallTime || 1 != dwCurrUseWUServer){
		bRet =  false;
	}

	RegCloseKey(hSubKey);
	RegCloseKey(hGPOKey);
	RegCloseKey(hKey);

	pGPO->Release();
	::CoUninitialize();
	return bRet;
}

std::wstring CPolicyTool::QueryWindowUpdateDate()
{
	std::wstring sOut(_T(""));
	::CoInitialize(NULL);
	//��ȡUpdateSearcher��ָ��
	IUpdateSearcher* pUpdateSearch; 
	if(SUCCEEDED(CoCreateInstance(CLSID_UpdateSearcher,NULL,CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER ,
		IID_IUpdateSearcher,(VOID**)&pUpdateSearch)))
	{
		//��ȡ�ܸ�������
		long HistoryCount;
		if ( SUCCEEDED(pUpdateSearch->GetTotalHistoryCount(&HistoryCount)))
		{
			//�ж��Ƿ��м�¼
			if(HistoryCount > 0)
			{
				IUpdateHistoryEntryCollection *pUpdateHistoryC;
				if ( SUCCEEDED(pUpdateSearch->QueryHistory(0, HistoryCount, &pUpdateHistoryC)) ) 
				{
					//MS: in descending chronological order.ʱ�併�����У����ֻȡ��һ�����������һ��
					IUpdateHistoryEntry *pLastUpdate;
					DATE date;		
					BSTR title;
					std::wstring sLastUpdateDate(_T(""));
					std::wstring sLastUpdateTitle(_T(""));
					if(SUCCEEDED(pUpdateHistoryC->get_Item(0,&pLastUpdate)))
					{
						if(SUCCEEDED(pLastUpdate->get_Date(&date)))
						{
							TCHAR szBuffer[256];
							RtlZeroMemory(szBuffer,256);

							SYSTEMTIME st;
							VariantTimeToSystemTime(date,&st);
							swprintf(szBuffer,256,_T("%04d%02d%02d"),st.wYear,st.wMonth,st.wDay);

							//COleDateTime oLastUpdateDate(date);
							//swprintf(szBuffer,256,_T("%04d%02d%02d"),oLastUpdateDate.GetYear(),oLastUpdateDate.GetMonth(),oLastUpdateDate.GetDay());
							//_stprintf(szBuffer,256,_T("%04d%02d%02d"),oLastUpdateDate.GetYear(),oLastUpdateDate.GetMonth(),oLastUpdateDate.GetDay());
							sLastUpdateDate = szBuffer;
						}
						if(SUCCEEDED(pLastUpdate->get_Title(&title)))
						{
							//assert(title != nullptr);
							std::wstring ws(title, SysStringLen(title));
							sLastUpdateTitle = ws;
						}
						sOut = sLastUpdateDate + _T(":") + sLastUpdateTitle;
						pLastUpdate->Release();
					}

					//long Count;
					//if ( SUCCEEDED(pUpdateHistoryC->get_Count(&Count)) ) 
					//{
					//	//�������и��¼�¼
					//	long J;
					//	IUpdateHistoryEntry  *pHistoricalUpdate;
					//	DATE updateDate;
					//	BSTR title;
					//	BSTR description;
					//	char* lpTempstring=NULL;
					//	TCHAR* lpttt = _T("mesfafas");
					//	_bstr_t Vttmp;
					//	wchar_t *lpwwww=NULL;
					//	for (J = 0; J < Count; J++)
					//	{						
					//		if ( SUCCEEDED(pUpdateHistoryC->get_Item(J, &pHistoricalUpdate)) ) 
					//		{
					//			//��ȡ����
					//			if(SUCCEEDED(pHistoricalUpdate->get_Date(&updateDate))){
					//				COleDateTime oDate(updateDate);
					//				int year = oDate.GetYear();
					//				int month = oDate.GetMonth();
					//				int day = oDate.GetDay();

					//				TRACE3("datetime:%04d%02d%02d\n",year,month,day);

					//			}
					//			//��ȡ����
					//			if(SUCCEEDED(pHistoricalUpdate->get_Title(&title))){
					//				//lpTempstring = _com_util::ConvertBSTRToString(title);
					//				if(J > 150)
					//				{
					//					Vttmp = title;
					//					lpwwww = (wchar_t*)Vttmp;
					//				}
					//				//TRACE1("title:%s",lpwwww);

					//			}
					//			//��ȡȫ����Ϣ
					//			if(SUCCEEDED(pHistoricalUpdate->get_Description(&description)))
					//			{
					//			}
					//			//pHistoricalUpdate->get_Description();
					//			pHistoricalUpdate->Release();
					//		} 
					//	} // for (J = 0; J < Count; J++)
					//} // if ( SUCCEEDED(pUpdateHistoryC->get_Count(&Count)) ) 
					pUpdateHistoryC->Release();
				}
			}
			else
			{
				pUpdateSearch->Release();//��ס�ͷ�
				/*sOut = _T("No record found.");*/
				return sOut;
			}
		} 
		pUpdateSearch->Release();
	} 	
	::CoUninitialize();
	return sOut;
}

DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE,0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);
#define   GUID_CLASS_USB_DEVICE                   GUID_DEVINTERFACE_USB_DEVICE  
const GUID intfce = GUID_CLASS_USB_DEVICE;

std::wstring CPolicyTool::QueryUsb()
{
	std::wstring sOut(_T(""));

	//��ȡ�豸��Ϣ�� - HDEVINFO
	HDEVINFO hDevInfo = INVALID_HANDLE_VALUE; //DeviceInfo�ľ��
	SP_DEVINFO_DATA DeviceInfoData;			 //�豸��Ϣ�ṹ��
	RtlZeroMemory(&DeviceInfoData, sizeof(SP_DEVINFO_DATA)); // ��ʼ��DeviceInfoData
	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA); 

	hDevInfo = SetupDiGetClassDevs(&intfce,0,0,DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);//��ȡ�豸��Ϣ����

	if(INVALID_HANDLE_VALUE == hDevInfo)
	{
		return sOut;
	}

	SP_DEVICE_INTERFACE_DATA DevInterface;	//Device�ӿ�
	PSP_DEVICE_INTERFACE_DETAIL_DATA DevInterface_Detail; //Device�ӿ���ϸ��Ϣ	

	DevInterface.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
	int nDevcount = 0;
	DWORD size = 0;

	//ö��hDevInfo Set�е������豸�ӿ�,���е��豸������0��ʼ
	while (SetupDiEnumDeviceInterfaces(hDevInfo, 
		0,
		//&DeviceInfoData,
		&intfce, 
		nDevcount, 
		&DevInterface)) 
	{
		TCHAR location[512];		//SPDRP_LOCATION_INFORMATION
		TCHAR interfacename[512];	//�豸����

		nDevcount++;

		SetupDiGetDeviceInterfaceDetail(hDevInfo, &DevInterface, 0, 0, &size, 0);

		DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		//���������ڴ�
		DevInterface_Detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)calloc(1, size); //arg1=��������,arg2=������С

		if (DevInterface_Detail) 
		{
			DevInterface_Detail->cbSize = sizeof (SP_DEVICE_INTERFACE_DETAIL_DATA);
			DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

			if (!SetupDiGetDeviceInterfaceDetail(hDevInfo, &DevInterface, DevInterface_Detail, size, 0, &DeviceInfoData)) 
			{
				DWORD dwError = GetLastError();
				TCHAR lpErrorMsg[512];
				FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0,dwError, 0,lpErrorMsg,1024, NULL);
				free(DevInterface_Detail);
				SetupDiDestroyDeviceInfoList(hDevInfo);
				break;
			}

			//�豸Path���ӿ�����
			_tcscpy(interfacename, DevInterface_Detail->DevicePath);
			free(DevInterface_Detail);
			std::wstring sInterface(interfacename);
			//ȡ��PID��VID
			std::wstring sTmp,sTmp1;
			int nIndexSharp = sInterface.find_first_of(L'#');
			sTmp1 = sInterface.substr(nIndexSharp + 1,sInterface.length() - nIndexSharp - 1);//ȡ���ӵ�һ�����ſ�ʼ���Ӵ�
			nIndexSharp = sTmp1.find_first_of(L'#');
			sTmp = sTmp1.substr(0,nIndexSharp);
			//sOut = sOut + _T("VID&PID :");
			sOut += sTmp;
			sOut += _T("#");
			sTmp = sTmp1.substr(nIndexSharp + 1,sTmp1.length() - nIndexSharp - 1);//ȡ���ӵڶ���#�ſ�ʼ���ִ�
			nIndexSharp = sTmp.find_first_of(L'#');
			sTmp = sTmp.substr(0,nIndexSharp);
			sOut += sTmp;
			sOut += _T(";");

			//ȡ������ǲ���
			nIndexSharp = sInterface.find_last_of(L'#');
			sTmp = sInterface.substr(nIndexSharp + 1,sInterface.length() - nIndexSharp - 1);
			//��\ȫ����#(��0,1,3λ)
			sInterface[0] = L'#';
			sInterface[1] = L'#';
			sInterface[3] = L'#';
			//size_t pos;
			//while(pos = sInterface.find_first_of(_T("\\")) >= 0)
			//{
			//	sInterface.replace(pos,1,_T("#"));
			//}
			
			//nIndexSharp = sTmp.find_first_of(L'#');
			//std::wstring sHardwareId = sTmp.substr(0,nIndexSharp);
			//��ע����ȡ��ַ��Ϣ���õ�ע����\HEKY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\xxx
			//CurrentControlSet,
			//std::wstring sKey = _T("SYSTEM\\CurrentControlSet\\Enum\\USB\\");
			std::wstring sKey = _T("SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\");
			sKey = sKey + sTmp + _T("\\") + sInterface + _T("\\Control");
			//std::wstring sKey = _T("SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{a5dcbf10-6530-11d2-901f-00c04fb951ed}\\##?#USB#Vid_0781&Pid_5530#20051739900CC5828313#{a5dcbf10-6530-11d2-901f-00c04fb951ed}\\Control");
			//sKey += sHardwareId;
			HKEY hKey;
			FILETIME ftLastWriteTime;
			if(ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,sKey.c_str(),0,KEY_READ,&hKey))
			{
				if(ERROR_SUCCESS == RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,&ftLastWriteTime))
				{
					COleDateTime oLastWriteTime(ftLastWriteTime);
					CString strLastWriteTime = oLastWriteTime.Format(_T("%Y-%m-%d %H:%M:%S"));
					//sOut = sOut + _T("Plug-in time: ") + strLastWriteTime.GetBuffer();
					//sOut += _T("  \n");
				}
			}


			DWORD dataType;
			size = sizeof(location);
			location[0] = 0;
			if (!SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_LOCATION_INFORMATION, &dataType, (LPBYTE)location, size, 0))
			//if (!SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_HARDWAREID, &dataType, (LPBYTE)location, size, 0))
			//if (!SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_FRIENDLYNAME, &dataType, (LPBYTE)location, size, 0))
			{
				SetupDiDestroyDeviceInfoList(hDevInfo);
				break;
			}
			//sOut += _T("Name:  ");
			//sOut += (TCHAR*)location;
			//sOut += _T(";\n");
		}
	}
	if(hDevInfo)
	{
		SetupDiDestroyDeviceInfoList(hDevInfo);
		if(nDevcount == 0)
		{
			return sOut;
		}
	}
	return sOut;
}

#define MAX_SIZE_CERT_NAME 1024
PCCERT_CONTEXT	CPolicyTool::FindCertificate(const HCERTSTORE hStore,const TCHAR* CertSearchString)
{
	PCCERT_CONTEXT capiCertificate = NULL;
	DWORD dType = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
	TCHAR certname [MAX_SIZE_CERT_NAME] = {0};

	for(;;)
	{
		capiCertificate = CertEnumCertificatesInStore(hStore, capiCertificate);
		if (NULL == capiCertificate)
		{
			break;
		}

		if (FALSE ==CertGetNameString(capiCertificate, CERT_NAME_RDN_TYPE,0, &dType, certname, MAX_SIZE_CERT_NAME))
		{
			CertFreeCertificateContext(capiCertificate);
			capiCertificate = NULL;
			break;
		}

		if ((0 == wcsncmp(certname, CertSearchString, MAX_SIZE_CERT_NAME)) &&	(capiCertificate->dwCertEncodingType == X509_ASN_ENCODING))
		{
			break;
		}
	}
	return capiCertificate;
}


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
bool CPolicyTool::QueryCert(const std::wstring &sCertSubject)
{
	bool bRet(false);

	//��CurrentUser store
	HCERTSTORE hSysStore = NULL;
	PCCERT_CONTEXT  pDesiredCert = NULL;   // Set to NULL for the first 
	/*LPCTSTR lpszCertSubject = _T("China Mobile Group Guangdong Co., Ltd. VPN Root CA");*/
	if(hSysStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,          // The store provider type
		0,                               // The encoding type is
		// not needed
		NULL,                            // Use the default HCRYPTPROV
		//CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
		CERT_SYSTEM_STORE_LOCAL_MACHINE,
		// registry location
		_T("Root")                            // The store name as a Unicode //��װ�������εĸ�Ŀ¼��֤��
		// string
		))
	{		
		if(pDesiredCert = FindCertificate(hSysStore,sCertSubject.c_str()))
		{
			bRet = true;
		}
		//*************************************************************
		//CERT_NAME_BLOB subjectname = {0};
		//DWORD size(0);
		////TCHAR sSN[] = _T("C = CN;O = China Mobile Group Guangdong Co.; Ltd, OU = SSLVPN CA Center; CN = China Mobile Group Guangdong Co., Ltd. VPN Root CA");
		//TCHAR sSN[] = _T("CN=\"China Mobile Group Guangdong Co., Ltd. VPN Root CA\", OU=SSLVPN CA Center, O=\"China Mobile Group Guangdong Co., Ltd\", C=CN");
		//bRet = CertStrToName(MY_ENCODING_TYPE,sSN,CERT_X500_NAME_STR/*CERT_OID_NAME_STR*/, NULL, NULL, &size, NULL);
		//if(TRUE == bRet)
		//{
		//	subjectname.pbData  = (BYTE*)malloc(size);
		//	subjectname.cbData = size;

		//	bRet = CertStrToName(MY_ENCODING_TYPE ,sSN, CERT_X500_NAME_STR, NULL, subjectname.pbData, &subjectname.cbData, NULL);
		//	if(TRUE == bRet)
		//	{
		//		pDesiredCert = CertFindCertificateInStore(hSysStore, MY_ENCODING_TYPE, 0, CERT_FIND_SUBJECT_NAME, &subjectname, NULL);
		//		pDesiredCert = CertFindCertificateInStore(hSysStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, &subjectname, NULL);
		//		int i = 1;
		//	}
		//}
		//*****************************************************************/
		//We have our store, let's do stuff with it
		/*if(pDesiredCert=CertFindCertificateInStore(
			hSysStore,
			MY_ENCODING_TYPE,           // Use X509_ASN_ENCODING.
			0,                          // No dwFlags needed. 
			CERT_FIND_SUBJECT_STR,      // Find a certificate with a
			//CERT_FIND_SUBJECT_NAME,
			//CERT_KEY_SPEC_PROP_ID,
			// subject that matches the string
			// in the next parameter.
			sCertSubject.c_str() ,           // The Unicode string to be found
			//&subjectname,
			// in a certificate's subject.
			NULL))                      // NULL for the first call to the
			// function. In all subsequent
			// calls, it is the last pointer
			// returned by the function.
		{
			DWORD dType = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
			TCHAR certname[1024] = {0};
			CertGetNameString(pDesiredCert, CERT_NAME_RDN_TYPE,	0, &dType, certname, 1024);
			CERT_CONTEXT cc={0};
			CERT_INFO ci = {0};
			CERT_NAME_BLOB subjectName = pDesiredCert->pCertInfo->Subject;
			TCHAR lpoutNamestr[1024] = {0};
			DWORD dwRet = CertNameToStr(pDesiredCert->dwCertEncodingType,&subjectName,CERT_X500_NAME_STR,lpoutNamestr,1024);
			TRACE0("The desired certificate was found. \n");
			pDesiredCert = CertFindCertificateInStore(hSysStore, MY_ENCODING_TYPE, 0, CERT_FIND_SUBJECT_NAME, &subjectName, NULL);

			bRet = true;
		}
		else
		{
			TRACE0("Could not find the desired certificate.\n");
		}*/
		//-------------------------------------------------------------------
		// Clean up. 

		if(pDesiredCert)
			CertFreeCertificateContext(pDesiredCert);
		if(hSysStore)
			CertCloseStore(
			hSysStore, 
			CERT_CLOSE_STORE_CHECK_FLAG);
	}
	else
	{
		//Error stuff
	}
	return bRet;
}

bool CPolicyTool::InstallCert(const std::wstring &sCertPath)
{
	//��֤��
	HANDLE hfile = INVALID_HANDLE_VALUE;	
	hfile = CreateFile(sCertPath.c_str(), FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

	//��ȡ�������ڴ�ӳ��
	HCERTSTORE pfxStore = 0;
	HCERTSTORE myStore = 0;
	HCERTSTORE hFileStore = 0;
	HANDLE hsection = 0;
	void* pfx = NULL;
	PCCERT_CONTEXT pctx = NULL;
	hsection = CreateFileMapping(hfile, 0, PAGE_READONLY, 0, 0, 0);
	if (!hsection)
	{
		CloseHandle(hfile);
		CloseHandle(hsection);
		return false;
	}
	pfx = MapViewOfFile(hsection, FILE_MAP_READ, 0, 0, 0);
	if (!pfx)
	{
		CloseHandle(hfile);
		CloseHandle(hsection);
		return false;
	}
	int nFilesize=GetFileSize(hfile,0);

	//����֤��Context	
	DWORD err(0);
	pctx = CertCreateCertificateContext(MY_ENCODING_TYPE, (BYTE*)pfx,nFilesize );
	UnmapViewOfFile(pfx);
	CloseHandle(hsection);
	CloseHandle(hfile);
	if(pctx == NULL)
	{
		FreeHandles(hFileStore,pctx, pfxStore, myStore);   
		TRACE0( "Error in 'CertCreateCertificateContext'");
		return false;
	}

	// we open the store for the CA
	//��֤���̵�
	hFileStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE/*CERT_SYSTEM_STORE_CURRENT_USER*//*CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE*/, _T("Root") );
	if (!hFileStore)
	{
		err = GetLastError();
		FreeHandles(hFileStore,pctx, pfxStore, myStore);   
		TRACE0("Error in 'CertOpenStore'" );
		return false;
	}

	//���֤��Context���̵�
	if( !CertAddCertificateContextToStore(hFileStore, pctx, CERT_STORE_ADD_NEW, 0) )
	{
		err = GetLastError();
		if( CRYPT_E_EXISTS == err )
		{
			//            if( AfxMessageBox("An equivalent previous personal certificate already exists. Overwrite ? (Yes/No)", MB_YESNO) == IDYES)
			{
				if( !CertAddCertificateContextToStore(hFileStore, pctx , CERT_STORE_ADD_REPLACE_EXISTING, 0))
				{
					err = GetLastError();
					FreeHandles(hFileStore,pctx, pfxStore, myStore);
					TRACE0( "Error in 'CertAddCertificateContextToStore' in replace mode") ;                       
					return false;
				}
			}
		}
		else
		{
			FreeHandles(hFileStore, pctx , pfxStore , myStore);
			TRACE0( "Error in 'CertAddCertificateContextToStore'" );
			return false;
		}
	}
	return true;
}

void CPolicyTool::FreeHandles(HCERTSTORE hFileStore, PCCERT_CONTEXT pctx,     HCERTSTORE pfxStore, HCERTSTORE myStore )
{
	if (myStore)
		CertCloseStore(myStore, 0);

	if (pfxStore)
		CertCloseStore(pfxStore, CERT_CLOSE_STORE_FORCE_FLAG);

	if(pctx)
		CertFreeCertificateContext(pctx);

	if (hFileStore)
		CertCloseStore(hFileStore, 0);
}



std::wstring CPolicyTool::QueryMemoryType()
{
	std::wstring sReturn(_T(""));
	SMBiosData m_oSMBIOSData;
	if(m_oSMBIOSData.FetchSMBiosData())//��ȡ����
	{
		m_oSMBIOSData.EnumTables((DWORD)(&m_oSMBIOSData),EnumTablesCallback);//ö�ٱ��
		//DWORD dwBytesToOutput;
		//DWORD dwFileSize = m_oSMBIOSData.GetRawDataLength();//SMBIOSData�ܴ�С
		//BYTE*	lpBaseAddress = m_oSMBIOSData.GetRawData();//SMBIOSData�ĵ�ַ
		sReturn = sMemoryTypeInfoCollection;
		sMemoryTypeInfoCollection = _T("");
	}
	else
	{
		MessageBox(NULL,_T("FetchSMBiosData failed!"),NULL,MB_OK);
	}

	return sReturn;
}

