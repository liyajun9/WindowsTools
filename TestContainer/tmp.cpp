// This function imports a CA certificate...
int CAssistantDlg::ImportCACert(LPCTSTR szFileName)
{
	HANDLE hfile = INVALID_HANDLE_VALUE;


	BYTE pByte[4096] = {0} , pBinByte[8192]={0};
	unsigned long bytesRead = 0;
	unsigned long binBytes = 4096;


	// Open it...
	//打开文件
	hfile = CreateFile(szFileName, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (INVALID_HANDLE_VALUE == hfile)
		return -1;

	//读取文件的4096字节
	ReadFile( hfile , pByte, 4096, &bytesRead ,NULL );
	CloseHandle(hfile);

	//API，将字符串加密成BinaryA
	CryptStringToBinaryA( (LPCSTR)pByte , bytesRead ,CRYPT_STRING_BASE64HEADER , pBinByte , &binBytes ,NULL,NULL);


	return ImportCACert(pBinByte , binBytes );
}


BOOL CAssistantDlg::ConstructAppPath(LPCTSTR cerfilename)
{


	TCHAR szPath[MAX_PATH]={0};
	if( !GetModuleFileName( NULL, szPath, MAX_PATH ) )
	{
		printf("GetModuleFileName failed (%d)\n", GetLastError());
		return FALSE;
	}
	m_strpath.Format(_T("%s"),szPath);
	int find = m_strpath.ReverseFind('\\');
	if (find>0)
	{
		m_strpath=m_strpath.Left(find+1);
		m_strpath +=cerfilename;
		return TRUE;
	}
	return FALSE;
}


void CAssistantDlg::PrintfError(DWORD err , LPCTSTR szError)
{
	if( err == 0 )
	{
		MessageBox(_T("安装成功！"),_T("证书安装"),MB_OK);
	}
	else
	{//
		MessageBox(_T("安装失败！"),_T("证书安装"),MB_OK);
	}
}


// Global function for free handles...
void CAssistantDlg::FreeHandles(HCERTSTORE hFileStore, PCCERT_CONTEXT pctx,     HCERTSTORE pfxStore, HCERTSTORE myStore )
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
int CAssistantDlg::ImportCACert(BYTE* pBinByte , unsigned long binBytes)
{
	HCERTSTORE pfxStore = 0;
	HCERTSTORE myStore = 0;
	HCERTSTORE hFileStore = 0;
	PCCERT_CONTEXT pctx = NULL;
	DWORD err = 0;

	//创建证书Context
	pctx = CertCreateCertificateContext(MY_ENCODING_TYPE, (BYTE*)pBinByte , binBytes );
	if(pctx == NULL)
	{
		DWORD err = GetLastError();
		FreeHandles(hFileStore,pctx, pfxStore, myStore);   
		PrintfError( err ,  _T("Error in 'CertCreateCertificateContext'") );
		return err;
	}


	// we open the store for the CA
	//打开证书商店
	hFileStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE, L"Root" );
	if (!hFileStore)
	{
		DWORD err = GetLastError();
		FreeHandles(hFileStore,pctx, pfxStore, myStore);   
		PrintfError( err ,  _T("Error in 'CertOpenStore'") );
		return err;
	}

	//添加证书Context到商店
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
					PrintfError( err ,  _T("Error in 'CertAddCertificateContextToStore'") );                       
					return err;
				}
			}
		}
		else
		{
			FreeHandles(hFileStore, pctx , pfxStore , myStore);
			PrintfError( err ,  _T("Error in 'CertAddCertificateContextToStore'") );
			return err;
		}
	}
	FreeHandles(hFileStore,pctx, pfxStore, myStore);
	PrintfError(0 , NULL) ;
	return 0;
}


void CAssistantDlg::SetupSign(LPCTSTR signpath)
{
	ShellExecuteA(NULL,"open",signpath,NULL,NULL,  SW_SHOW  );
}


void CAssistantDlg::OnBnClickedButtonSign()
{
	// TODO: 在此添加控件通知处理程序代码


	//CString strpath;
	//TCHAR szPath[MAX_PATH]={0};
	//if( !GetModuleFileName( NULL, szPath, MAX_PATH ) )
	//{
	// printf("GetModuleFileName failed (%d)\n", GetLastError());
	// return ;
	//}
	//strpath.Format(_T("%s"),szPath);
	//int find = strpath.ReverseFind('\\');
	//if (find>0)
	//{
	// strpath=strpath.Left(find+1);
	// strpath +="Sign\\sign.bat";


	//}


	//SetupSign(strpath);
	ConstructAppPath(_T("MS_XS.cer"));
	ImportCACert(m_strpath);
}