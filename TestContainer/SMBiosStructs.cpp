#include "stdafx.h"
#include "SMBiosStructs.h"

#include <comdef.h>
#include <Wbemidl.h>
#include <string>

# pragma comment(lib, "wbemuuid.lib")

BOOL SMBiosData::bVersionAfterTwoPointSix = FALSE;

SMBiosData::SMBiosData()
{
	m_byMajorVersion = 0;
	m_byMinorVersion = 0;
	m_pbBIOSData = NULL;
	m_dwLen = 0;
}

SMBiosData::~SMBiosData()
{
	if(m_pbBIOSData)
		delete []m_pbBIOSData;
}

BOOL SMBiosData::GetData(SMBios_TYPE0& stSMBiosType0)
{
	DWORD dwTableSize;
	BYTE* pbData = GetNextTable(NULL,FALSE,0,dwTableSize);
	BYTE* pbSectionStart = pbData;
	
	if(pbData)
	{
		memset(&stSMBiosType0,0,sizeof(SMBios_TYPE0));
		//mandatory header
		stSMBiosType0.stHeader.bySection = *pbData++;
		stSMBiosType0.stHeader.byLength = *pbData++;
		stSMBiosType0.stHeader.wHandle = *(WORD*)pbData,pbData++,pbData++;
		
		//type specific data
		//START formatted section
		stSMBiosType0.byVendor = *pbData++;
		stSMBiosType0.byBiosVersion = *pbData++;
		stSMBiosType0.wBIOSStartingSegment = *(WORD*)pbData,pbData++,pbData++;
		
		stSMBiosType0.byBIOSReleaseDate = *pbData++;
		stSMBiosType0.byBIOSROMSize = *pbData++;
		for(int j = 0 ; j < 8 ; j++)
			stSMBiosType0.qwBIOSCharacteristics[j] = *pbData++;
		stSMBiosType0.byExtensionByte1 = *pbData++;
		stSMBiosType0.byExtensionByte2 = *pbData++;
		stSMBiosType0.bySystemBIOSMajorRelease = *pbData++;
		stSMBiosType0.bySystemBIOSMinorRelease = *pbData++;
		stSMBiosType0.byEmbeddedFirmwareMajorRelease = *pbData++;
		stSMBiosType0.byEmbeddedFirmwareMinorRelease = *pbData++;
		//END formatted section

		//START unformatted section
		pbSectionStart += stSMBiosType0.stHeader.byLength;
		
		stSMBiosType0.szVendor = GetString(pbSectionStart,stSMBiosType0.byVendor);
		stSMBiosType0.szBIOSVersion = GetString(pbSectionStart,stSMBiosType0.byBiosVersion);
		stSMBiosType0.szBIOSReleaseDate = GetString(pbSectionStart,stSMBiosType0.byBIOSReleaseDate);
		//END unformatted section
	}
	return (pbData != NULL);
}

BOOL SMBiosData::GetData(SMBios_TYPE1& stSMBiosType1)
{
	DWORD dwTableSize;
	BYTE* pbData = GetNextTable(NULL,FALSE,1,dwTableSize);
	BYTE* pbSectionStart = pbData;
	
	if(pbData)
	{
		memset(&stSMBiosType1,0,sizeof(SMBios_TYPE1));

		if(m_byMajorVersion >=2 && m_byMinorVersion > 0)
		{
			//mandatory header
			stSMBiosType1.stHeader.bySection = *pbData++;
			stSMBiosType1.stHeader.byLength = *pbData++;
			stSMBiosType1.stHeader.wHandle = *(WORD*)pbData,pbData++,pbData++;
		
			//type specific data
			//START formatted section
			stSMBiosType1.byManufacturer = *pbData++;
			stSMBiosType1.byProductName = *pbData++;
			stSMBiosType1.byVersion = *pbData++;
			stSMBiosType1.bySerialNumber = *pbData++;
		}

		if(m_byMajorVersion >=2 && m_byMinorVersion > 1)
		{
			for(int j = 0 ; j < 16 ; j++)
				stSMBiosType1.byUUID[j] = *pbData++;
			stSMBiosType1.byWakeupType = *pbData++;
		}

		if(m_byMajorVersion >=2 && m_byMinorVersion > 4)
		{
			stSMBiosType1.bySKUNumber = *pbData++;
			stSMBiosType1.byFamily = *pbData++;
		}
			//END formatted section

		//START unformatted section
		pbSectionStart += stSMBiosType1.stHeader.byLength;
		
		if(stSMBiosType1.byManufacturer)
			stSMBiosType1.szManufacturer = GetString(pbSectionStart,stSMBiosType1.byManufacturer);
		if(stSMBiosType1.byProductName)
			stSMBiosType1.szProductName = GetString(pbSectionStart,stSMBiosType1.byProductName);
		if(stSMBiosType1.byVersion)
			stSMBiosType1.szVersion = GetString(pbSectionStart,stSMBiosType1.byVersion);
		if(stSMBiosType1.bySerialNumber)
			stSMBiosType1.szSerialNumber = GetString(pbSectionStart,stSMBiosType1.bySerialNumber);
		if(stSMBiosType1.bySKUNumber)
			stSMBiosType1.szSKUNumber = GetString(pbSectionStart,stSMBiosType1.bySKUNumber);
		if(stSMBiosType1.byFamily)
			stSMBiosType1.szFamily = GetString(pbSectionStart,stSMBiosType1.byFamily);
		//END unformatted section
	}
	return (pbData != NULL);
}

BOOL SMBiosData::GetData(SMBios_TYPE2& stSMBiosType2)
{
	DWORD dwTableSize;
	BYTE* pbData = GetNextTable(NULL,FALSE,2,dwTableSize);
	BYTE* pbSectionStart = pbData;
	
	if(pbData)
	{
		memset(&stSMBiosType2,0,sizeof(SMBios_TYPE2));

		//mandatory header
		stSMBiosType2.stHeader.bySection = *pbData++;
		stSMBiosType2.stHeader.byLength = *pbData++;
		stSMBiosType2.stHeader.wHandle = *(WORD*)pbData,pbData++,pbData++;
		
		//type specific data
		//START formatted section
		stSMBiosType2.byManufacturer = *pbData++;
		stSMBiosType2.byProductName = *pbData++;
		stSMBiosType2.byVersion = *pbData++;
		stSMBiosType2.bySerialNumber = *pbData++;
		stSMBiosType2.byAssetTag = *pbData++;
		stSMBiosType2.byFeatureFlags = *pbData++;
		stSMBiosType2.byLocationInChassis = *pbData++;
		stSMBiosType2.wChassisHandle = *(WORD*)pbData,pbData++,pbData++;
		stSMBiosType2.byBoardType = *pbData++;
		stSMBiosType2.byNoOfContainedObjectHandles = *pbData++;

		for(int j = 0 ; j < stSMBiosType2.byNoOfContainedObjectHandles ; j++)
			stSMBiosType2.ContainedObjectHandles[j] = (WORD*)pbData,pbData++,pbData++;
		//END formatted section

		//START unformatted section
		pbSectionStart += stSMBiosType2.stHeader.byLength;
		
		if(stSMBiosType2.byManufacturer)
			stSMBiosType2.szManufacturer = GetString(pbSectionStart,stSMBiosType2.byManufacturer);
		if(stSMBiosType2.byProductName)
			stSMBiosType2.szProductName = GetString(pbSectionStart,stSMBiosType2.byProductName);
		if(stSMBiosType2.byVersion)
			stSMBiosType2.szVersion = GetString(pbSectionStart,stSMBiosType2.byVersion);
		if(stSMBiosType2.bySerialNumber)
			stSMBiosType2.szSerialNumber = GetString(pbSectionStart,stSMBiosType2.bySerialNumber);
		if(stSMBiosType2.byAssetTag)
			stSMBiosType2.szAssetTag = GetString(pbSectionStart,stSMBiosType2.byAssetTag);
		if(stSMBiosType2.byLocationInChassis)
			stSMBiosType2.szLocationInChassis = GetString(pbSectionStart,stSMBiosType2.byLocationInChassis);
		//END unformatted section
	}
	return (pbData != NULL);
}

BOOL SMBiosData::GetData(SMBios_TYPE3& stSMBiosType3)
{
	DWORD dwTableSize;
	BYTE* pbData = GetNextTable(NULL,FALSE,3,dwTableSize);
	BYTE* pbSectionStart = pbData;
	
	if(pbData)
	{
		memset(&stSMBiosType3,0,sizeof(SMBios_TYPE3));

		if(m_byMajorVersion >=2 && m_byMinorVersion > 0)
		{
			//mandatory header
			stSMBiosType3.stHeader.bySection = *pbData++;
			stSMBiosType3.stHeader.byLength = *pbData++;
			stSMBiosType3.stHeader.wHandle = *(WORD*)pbData,pbData++,pbData++;
			
			//type specific data
			//START formatted section
			stSMBiosType3.byManufacturer = *pbData++;
			stSMBiosType3.byType = *pbData++;
			stSMBiosType3.byVersion = *pbData++;
			stSMBiosType3.bySerialNumber = *pbData++;
			stSMBiosType3.byAssetTag = *pbData++;
		}

		if(m_byMajorVersion >=2 && m_byMinorVersion > 1)
		{
			stSMBiosType3.byBootupState = *pbData++;
			stSMBiosType3.byPowerSupplyState = *pbData++;
			stSMBiosType3.byThermalState = *pbData++;
			stSMBiosType3.bySecurityStatus = *pbData++;
		}

		if(m_byMajorVersion >=2 && m_byMinorVersion > 3)
		{
			stSMBiosType3.dwOEMdefined = *(DWORD*)pbData,pbData++,pbData++,pbData++,pbData++;
			stSMBiosType3.byHeight = *pbData++;
			stSMBiosType3.byNumberOfPowerCords = *pbData++;
			stSMBiosType3.byContainedElementCount = *pbData++;
			stSMBiosType3.byContainedElementRecordLength = *pbData++;
		}

		//END formatted section

		//START unformatted section
		pbSectionStart += stSMBiosType3.stHeader.byLength;
		
		if(stSMBiosType3.byManufacturer)
			stSMBiosType3.szManufacturer = GetString(pbSectionStart,stSMBiosType3.byManufacturer);
		if(stSMBiosType3.byVersion)
			stSMBiosType3.szVersion = GetString(pbSectionStart,stSMBiosType3.byVersion);
		if(stSMBiosType3.bySerialNumber)
			stSMBiosType3.szSerialNumber = GetString(pbSectionStart,stSMBiosType3.bySerialNumber);
		if(stSMBiosType3.byAssetTag)
			stSMBiosType3.szAssetTag = GetString(pbSectionStart,stSMBiosType3.byAssetTag);
		//END unformatted section
	}
	return (pbData != NULL);
}

BOOL SMBiosData::GetData(SMBios_TYPE4& stSMBiosType4)
{
	DWORD dwTableSize;
	BYTE* pbData = GetNextTable(NULL,FALSE,4,dwTableSize);
	BYTE* pbSectionStart = pbData;
	
	if(pbData)
	{
		memset(&stSMBiosType4,0,sizeof(SMBios_TYPE4));

		if(m_byMajorVersion >=2 && m_byMinorVersion > 0)
		{
			//mandatory header
			stSMBiosType4.stHeader.bySection = *pbData++;
			stSMBiosType4.stHeader.byLength = *pbData++;
			stSMBiosType4.stHeader.wHandle = *(WORD*)pbData,pbData++,pbData++;
			
			//type specific data
			//START formatted section
			stSMBiosType4.bySocketDesignation = *pbData++;
			stSMBiosType4.byProcessorType = *pbData++;
			stSMBiosType4.byProcessorFamily = *pbData++;
			stSMBiosType4.byProcessorManufacturer = *pbData++;
			for(int j = 0 ; j < 8; j++)
				stSMBiosType4.qwProcessorID[j] = *pbData++;
			stSMBiosType4.byProcessorVersion = *pbData++;
			stSMBiosType4.byVoltage = *pbData++;

			stSMBiosType4.wExternalClock = *pbData,pbData++,pbData++;
			stSMBiosType4.wMaxSpeed = *pbData,pbData++,pbData++;
			stSMBiosType4.wCurrentSpeed = *pbData,pbData++,pbData++;

			stSMBiosType4.byStatus = *pbData++;
			stSMBiosType4.byProcessorUpgrade = *pbData++;
		}

		if(m_byMajorVersion >=2 && m_byMinorVersion > 1)
		{
			stSMBiosType4.wL1CacheHandle = *(WORD*)pbData,pbData++,pbData++;
			stSMBiosType4.wL2CacheHandle = *(WORD*)pbData,pbData++,pbData++;
			stSMBiosType4.wL3CacheHandle = *(WORD*)pbData,pbData++,pbData++;
		}

		if(m_byMajorVersion >=2 && m_byMinorVersion > 3)
		{
			stSMBiosType4.bySerialNumber = *pbData++;
			stSMBiosType4.byAssetTagNumber = *pbData++;
			stSMBiosType4.byPartNumber = *pbData++;
		}

		//END formatted section

		//START unformatted section
		pbSectionStart += stSMBiosType4.stHeader.byLength;
		
		if(stSMBiosType4.bySocketDesignation)
			stSMBiosType4.szSocketDesignation = GetString(pbSectionStart,stSMBiosType4.bySocketDesignation);
		if(stSMBiosType4.byProcessorManufacturer)
			stSMBiosType4.szProcessorManufacturer = GetString(pbSectionStart,stSMBiosType4.byProcessorManufacturer);
		if(stSMBiosType4.bySerialNumber)
			stSMBiosType4.szSerialNumber = GetString(pbSectionStart,stSMBiosType4.bySerialNumber);
		if(stSMBiosType4.byAssetTagNumber)
			stSMBiosType4.szAssetTagNumber = GetString(pbSectionStart,stSMBiosType4.byAssetTagNumber);
		if(stSMBiosType4.byPartNumber)
			stSMBiosType4.szPartNumber = GetString(pbSectionStart,stSMBiosType4.byPartNumber);
		//END unformatted section
	}
	return (pbData != NULL);
}

BOOL SMBiosData::GetData(SMBios_TYPE11& stSMBiosType11)
{
	DWORD dwTableSize;
	BYTE* pbData = GetNextTable(NULL,FALSE,11,dwTableSize);
	BYTE* pbSectionStart = pbData;
	
	if(pbData)
	{
		memset(&stSMBiosType11,0,sizeof(SMBios_TYPE11));
		//mandatory header
		stSMBiosType11.stHeader.bySection = *pbData++;
		stSMBiosType11.stHeader.byLength = *pbData++;
		stSMBiosType11.stHeader.wHandle = *(WORD*)pbData,pbData++,pbData++;
		
		//type specific data
		//START formatted section
		stSMBiosType11.byCountStrings = *pbData++;
		
		//START unformatted section
		pbSectionStart += stSMBiosType11.stHeader.byLength;
		
		for(int j = 0 ; j < stSMBiosType11.byCountStrings ; j++)
			stSMBiosType11.szStrings[j] = GetString(pbSectionStart,j + 1);
		//END unformatted section
	}
	return (pbData != NULL);
}

BYTE* SMBiosData::GetNextTable(BYTE* const pbData,BOOL bIgnoreTableType,BYTE byTableType,DWORD& dwTotalTableSize)
{
	BYTE byCurrentSection = 0;
	BYTE byLengthOfFormattedSection = 0;
	BYTE*	pbNextTable = NULL;
	BYTE*	pbCurrentTable = NULL;
	
	if(pbData)
		pbCurrentTable = pbData;
	else
		pbCurrentTable = m_pbBIOSData;
	int j = pbCurrentTable - m_pbBIOSData;

	for( ; j < m_dwLen; )
	{
		byCurrentSection = pbCurrentTable[0];

		if((FALSE == bIgnoreTableType && byCurrentSection == byTableType && pbCurrentTable != pbData) ||
		   (TRUE == bIgnoreTableType && pbCurrentTable != pbData))
		{
			byLengthOfFormattedSection = pbCurrentTable[1];

			BYTE* pUnformattedSection = pbCurrentTable + byLengthOfFormattedSection;

			//now look for 2 zeroes.
			for(int m = 0 ; ; m++)
			{
				if(pUnformattedSection[m] == 0 && pUnformattedSection[m+1] == 0)
				{
					dwTotalTableSize = byLengthOfFormattedSection + m + 1;
					break;
				}
			}
			pbNextTable = pbCurrentTable;
			break;
		}

		byLengthOfFormattedSection = pbCurrentTable[1];

		BYTE* pUnformattedSection = pbCurrentTable + byLengthOfFormattedSection;

		//now look for 2 zeroes.
		for(int m = 0 ; ; m++)
		{
			if(pUnformattedSection[m] == 0 && pUnformattedSection[m+1] == 0)
			{
				j = j + byLengthOfFormattedSection + m + 2;
				dwTotalTableSize = byLengthOfFormattedSection + m + 1;
				pbCurrentTable = pbCurrentTable + byLengthOfFormattedSection + m + 2;
				break;
			}
		}

	}
	return pbNextTable;
}

//BYTE* SMBiosData::GetTableByIndex(BYTE byIndex,DWORD& dwTotalTableSize)
//{
//	BYTE	byLengthOfFormattedSection = 0;
//	BYTE*	pbNextTable = NULL;
//	BYTE*	pbCurrentTable = NULL;
//	
//	pbCurrentTable = m_pbBIOSData;
//
//	for(int j = 0, nIndex = 0 ; j < m_dwLen; )
//	{
//		byLengthOfFormattedSection = pbCurrentTable[1];
//
//		BYTE* pUnformattedSection = pbCurrentTable + byLengthOfFormattedSection;
//
//		//now look for 2 zeroes.
//		for(int m = 0 ; ; m++)
//		{
//			dwTotalTableSize = 0;
//			if(pUnformattedSection[m] == 0 && pUnformattedSection[m+1] == 0)
//			{
//				j = j + byLengthOfFormattedSection + m + 2;
//				dwTotalTableSize = byLengthOfFormattedSection + m + 1;
//				break;
//			}
//		}
//		
//		if(nIndex == byIndex)
//		{
//			pbNextTable = pbCurrentTable;
//			break;
//		}
//		else
//		{
//			pbCurrentTable = pbCurrentTable + byLengthOfFormattedSection + m + 2;
//			nIndex++;
//		}
//
//	}
//	return pbNextTable;
//}

char* SMBiosData::GetString(BYTE* pbData,BYTE byIndex)
{
	char* pStr = NULL;
	
	BYTE j = 0;
	do
	{
		pStr = (char*)pbData;
		pbData += (strlen(pStr) + 1);
		j++;
	}
	while(j < byIndex);
	return pStr;
}

BOOL SMBiosData::FetchSMBiosData()
{
	BOOL bRet = FALSE;
	HRESULT hres;

    // Initialize COM.
    hres =  CoInitializeEx(0, /*COINIT_MULTITHREADED*/COINIT_APARTMENTTHREADED); 
    if (FAILED(hres))
    {
        return FALSE;              // Program has failed.
    }

    // Obtain the initial locator to Windows Management
    // on a particular host computer.
    IWbemLocator *pLoc = 0;

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres))
    {
        CoUninitialize();
        return FALSE;       // Program has failed.
    }
    IWbemServices *pSvc = 0;

    // Connect to the root\cimv2 namespace with the
    // current user and obtain pointer pSvc
    // to make IWbemServices calls.

    hres = pLoc->ConnectServer(
        
        _bstr_t(L"ROOT\\WMI"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale
        NULL,                    // Security flags                 
        0,                       // Authority       
        0,                       // Context object
        &pSvc                    // IWbemServices proxy
        );                              
    
    if (FAILED(hres))
    {
        pLoc->Release();     
        CoUninitialize();
        return FALSE;                // Program has failed.
    }

    // Set the IWbemServices proxy so that impersonation
    // of the user (client) occurs.
    hres = CoSetProxyBlanket(
       
       pSvc,                         // the proxy to set
       RPC_C_AUTHN_WINNT,            // authentication service
       RPC_C_AUTHZ_NONE,             // authorization service
       NULL,                         // Server principal name
       RPC_C_AUTHN_LEVEL_CALL,       // authentication level
       RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
       NULL,                         // client identity 
       EOAC_NONE                     // proxy capabilities     
    );

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return FALSE;               // Program has failed.
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->CreateInstanceEnum( L"MSSMBios_RawSMBiosTables", 0, NULL, &pEnumerator);
    
    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return FALSE;               // Program has failed.
    }
    else
    { 
        do
        {
            IWbemClassObject* pInstance = NULL;
            ULONG dwCount = NULL;

            hres = pEnumerator->Next(
                WBEM_INFINITE,
                1,
                &pInstance,
                &dwCount);      
			if(SUCCEEDED(hres))
			{
				VARIANT varBIOSData;
				VariantInit(&varBIOSData);
				CIMTYPE             type;

				hres = pInstance->Get(bstr_t("SmbiosMajorVersion"),0,&varBIOSData,&type,NULL);
				if(FAILED(hres))
				{
					VariantClear(&varBIOSData);
				}
				else
				{
					m_byMajorVersion = varBIOSData.iVal;
					VariantInit(&varBIOSData);
					hres = pInstance->Get(bstr_t("SmbiosMinorVersion"),0,&varBIOSData,&type,NULL);
					//added
					std::string s1 = (LPCSTR)_bstr_t(varBIOSData);
					if(0 < strcmp(s1.c_str(),"6"))
					{
						bVersionAfterTwoPointSix = TRUE;
					}
					
					if(FAILED(hres))
					{
						VariantClear(&varBIOSData);
					}
					else
					{
						m_byMinorVersion = varBIOSData.iVal;
						VariantInit(&varBIOSData);
						hres = pInstance->Get(bstr_t("SMBiosData"),0,&varBIOSData,&type,NULL);
						if(SUCCEEDED(hres))
						{
							if ( ( VT_UI1 | VT_ARRAY  ) != varBIOSData.vt )
							{
							}
							else
							{
								SAFEARRAY           *parray = NULL;
								parray = V_ARRAY(&varBIOSData);
								BYTE* pbData = (BYTE*)parray->pvData;

								m_dwLen = parray->rgsabound[0].cElements;
								m_pbBIOSData = new BYTE[m_dwLen];
								memcpy(m_pbBIOSData,pbData,m_dwLen);

								bRet = TRUE;
							}
						}
						VariantClear(&varBIOSData);
					}
				}
				break;
			}
    
        } while (hres == WBEM_S_NO_ERROR);
    }
	
    // Cleanup
    // ========
    pSvc->Release();
    pLoc->Release();     
    CoUninitialize();

	return bRet;
}

void SMBiosData::EnumTables(DWORD dwParam, ENUMPROC pfnEnumProc)
{
	if(pfnEnumProc)
	{
		DWORD dwTableSize;
		BYTE* pbData = NULL;
		EnumTableStruct stEnumTableStruct;
		stEnumTableStruct.dwIndex = 0;
		do
		{
			pbData = GetNextTable(pbData,TRUE,0,dwTableSize);
			if(pbData)
			{
				stEnumTableStruct.dwOffsetOfTableFromBeginning = pbData - m_pbBIOSData;
				stEnumTableStruct.dwTableSize = dwTableSize;
				stEnumTableStruct.dwTableType = *pbData;
				(*pfnEnumProc)(dwParam,&stEnumTableStruct);
				stEnumTableStruct.dwIndex++;
			}
		}
		while(pbData);
	}
}