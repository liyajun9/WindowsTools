
// TestContainerDlg.h : header file
//

#pragma once


// CTestContainerDlg dialog
class CTestContainerDlg : public CDialogEx
{
// Construction
public:
	CTestContainerDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_TESTCONTAINER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
private:
	CString m_strCertSubject;
	CString m_strInstallCertResult;
	CString m_strCertPath;
	CString m_strCertSubject2;
	CString m_strMemory;
	CString m_strConfigUpdate;
public:
	afx_msg void OnBnClickedOk3();
	afx_msg void OnBnClickedQueryusb();
	afx_msg void OnBnClickedOk2();
	afx_msg void OnBnClickedQueryusb2();
	afx_msg void OnBnClickedQueryusb3();
	afx_msg void OnBnClickedConfigupdate();
};
