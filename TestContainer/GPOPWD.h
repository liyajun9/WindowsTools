#pragma once
#include <string>

//#include <Ntsecapi.h>
//#define SAM_SERVER_CONNECT               0x0001
//#define SAM_SERVER_SHUTDOWN              0x0002
//#define SAM_SERVER_INITIALIZE            0x0004
//#define SAM_SERVER_CREATE_DOMAIN         0x0008
//#define SAM_SERVER_ENUMERATE_DOMAINS     0x0010
//#define SAM_SERVER_LOOKUP_DOMAIN         0x0020
//
//#ifndef _NTDEF_
//typedef LSA_UNICODE_STRING UNICODE_STRING, *PUNICODE_STRING;
//typedef LSA_STRING STRING, *PSTRING ;
//#endif
//
//#ifndef _NTSAM_SAM_HANDLE_               // ntsubauth
//typedef PVOID SAM_HANDLE, *PSAM_HANDLE;  // ntsubauth
//#define _NTSAM_SAM_HANDLE_               // ntsubauth
//#endif                                   // ntsubauth
//typedef ULONG SAM_ENUMERATE_HANDLE, *PSAM_ENUMERATE_HANDLE;
//
//typedef struct _OBJECT_ATTRIBUTES {
//	ULONG           Length;
//	HANDLE          RootDirectory;
//	PUNICODE_STRING ObjectName;
//	ULONG           Attributes;
//	PVOID           SecurityDescriptor;
//	PVOID           SecurityQualityOfService;
//}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
//
//
//typedef NTSTATUS (WINAPI* pfnSamConnect)(
//	/*__in_opt*/  PUNICODE_STRING ServerName,
//	/*__out*/     PSAM_HANDLE ServerHandle,
//	/*__in*/      ACCESS_MASK DesiredAccess,
//	/*__in*/     POBJECT_ATTRIBUTES ObjectAttributes
//	);
//typedef NTSTATUS (WINAPI* pfnSamEnumerateDomainsInSamServer)(
//	/*__in*/       SAM_HANDLE ServerHandle,
//	/*__inout*/     PSAM_ENUMERATE_HANDLE EnumerationContext,
//	/*__deref_out*/ PVOID *Buffer,
//	/*__in*/        ULONG PreferedMaximumLength,
//	/*__out*/       PULONG CountReturned
//	);

class CPolicyTool
{
public:
	CPolicyTool(void);
	~CPolicyTool(void);
	bool QueryPasswordPolicies();
	bool SetPasswordPolicies();
	bool ConfigureWindowsUpdate();
	bool QueryWindowsUPdate();
	std::wstring QueryWindowUpdateDate();
	std::wstring QueryUsb();
	//temp
	bool QueryCert(const std::wstring &sCertSubject);
	bool InstallCert(const std::wstring &sCertPath);
	// 
	std::wstring QueryMemoryType();
//public:
//	pfnSamConnect _SamConnect;
//	pfnSamEnumerateDomainsInSamServer _SamEnumerateDomainsInSamServer;
private:
	void FreeHandles(HCERTSTORE hFileStore, PCCERT_CONTEXT pctx,     HCERTSTORE pfxStore, HCERTSTORE myStore );
	static PCCERT_CONTEXT FindCertificate(const HCERTSTORE hStore,const TCHAR* CertSearchString);
};
