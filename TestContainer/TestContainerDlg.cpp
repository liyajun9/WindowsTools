
// TestContainerDlg.cpp : implementation file
//

#include "stdafx.h"
#include "TestContainer.h"
#include "TestContainerDlg.h"
#include "afxdialogex.h"
#include "GPOPWD.h"
#include <string>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CTestContainerDlg dialog




CTestContainerDlg::CTestContainerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CTestContainerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CTestContainerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_CERTSUBJECT, m_strCertSubject);
	DDX_Text(pDX, IDC_INSTALLRESULT, m_strInstallCertResult);
	DDX_Text(pDX, IDC_EDIT_CERTPATH, m_strCertPath);
	DDX_Text(pDX, IDC_EDIT_CERTSUBJECT2, m_strCertSubject2);
	//DDX_Text(pDX, IDC_MEMORY, m_strMemory);
}

BEGIN_MESSAGE_MAP(CTestContainerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CTestContainerDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDOK3, &CTestContainerDlg::OnBnClickedOk3)
	ON_BN_CLICKED(IDQUERYUSB, &CTestContainerDlg::OnBnClickedQueryusb)
	ON_BN_CLICKED(IDOK2, &CTestContainerDlg::OnBnClickedOk2)
	ON_BN_CLICKED(IDQUERYUSB2, &CTestContainerDlg::OnBnClickedQueryusb2)
	ON_BN_CLICKED(IDQUERYUSB3, &CTestContainerDlg::OnBnClickedQueryusb3)
	ON_BN_CLICKED(IDCONFIGUPDATE, &CTestContainerDlg::OnBnClickedConfigupdate)
END_MESSAGE_MAP()


// CTestContainerDlg message handlers

BOOL CTestContainerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CTestContainerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CTestContainerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CTestContainerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//查询证书
void CTestContainerDlg::OnBnClickedOk()
{
	UpdateData();
	CPolicyTool GPO;
	const std::wstring sCertSubject = m_strCertSubject.GetBuffer();
	//const std::wstring  sCertSubject= _T("China Mobile Group Guangdong Co., Ltd. VPN Root CA");
	if(GPO.QueryCert(sCertSubject))
	{
		SetDlgItemText(IDC_FINDCERTRESULT,_T("证书已安装"));
	}
	else
	{
		SetDlgItemText(IDC_FINDCERTRESULT,_T("证书不存在"));
	}
	// TODO: Add your control notification handler code here
	//CDialogEx::OnOK();
}

//安装证书
void CTestContainerDlg::OnBnClickedOk2()
{
	// TODO: Add your control notification handler code here
	UpdateData();
	CPolicyTool GPO;
	const std::wstring sCertPath = m_strCertPath.GetBuffer();
	const std::wstring sCertSubject = m_strCertSubject2.GetBuffer();
	//const std::wstring  sCertSubject= _T("China Mobile Group Guangdong Co., Ltd. VPN Root CA");
	//const std::wstring  sCertPath= _T("C:\\VPNRootCA.der");
	if(GPO.QueryCert(sCertSubject))
	{
		SetDlgItemText(IDC_INSTALLRESULT,_T("证书已导入,不需要重新安装"));
	}
	else
	{
		if(GPO.InstallCert(sCertPath))
		{
			SetDlgItemText(IDC_INSTALLRESULT,_T("安装成功!"));
		}
		else
		{
			SetDlgItemText(IDC_INSTALLRESULT,_T("安装失败"));
		}
	}
}



void CTestContainerDlg::OnBnClickedOk3()
{
	// TODO: Add your control notification handler code here
	CPolicyTool GPO;
	std::wstring strUpdateInfo = GPO.QueryWindowUpdateDate();
	SetDlgItemText(IDC_UPDATETIME,strUpdateInfo.c_str());
}


void CTestContainerDlg::OnBnClickedQueryusb()
{
	// TODO: Add your control notification handler code here
	CPolicyTool GPO;
	std::wstring strUsbInfo = GPO.QueryUsb();
	SetDlgItemText(IDC_USBINFO,strUsbInfo.c_str());
}



void CTestContainerDlg::OnBnClickedQueryusb2()
{
	// TODO: Add your control notification handler code here
	CPolicyTool GPO;
	std::wstring sMemory = GPO.QueryMemoryType();
	SetDlgItemText(IDC_MEMORY,sMemory.c_str());
}


void CTestContainerDlg::OnBnClickedQueryusb3()
{
	// TODO: Add your control notification handler code here
	CPolicyTool GPO;
	if(GPO.QueryWindowsUPdate())
	{
		SetDlgItemText(IDC_CONFIGURUPDATE,_T("设置正确"));
	}
	else
	{
		SetDlgItemText(IDC_CONFIGURUPDATE,_T("设置错误"));
	}
}


void CTestContainerDlg::OnBnClickedConfigupdate()
{
	// TODO: Add your control notification handler code here
	CPolicyTool GPO;
	bool bret = GPO.ConfigureWindowsUpdate();
}
