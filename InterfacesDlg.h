
//This is the code for the first dialog interface of the program
//The first dialog is for selection of the interface

#pragma once


// CInterfacesDlg dialog

class CInterfacesDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CInterfacesDlg)

public:
	CInterfacesDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CInterfacesDlg();

// Dialog Data
//#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLG_INTERFACES };
//#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
private:
	CListCtrl m_listCtrlAdapters;//list that shows adapters
	LPVOID m_lpCap;
	int m_nSel;//selected index
protected:
	afx_msg void OnLvnItemchangedListAdapter(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedOk();
	virtual BOOL OnInitDialog(); //initialize function 
	void GetAdaptersAndInsert();//Here you can get network adapters and see them in list

public:
	void SetPcapPoint(LPVOID lParam);	
};	
