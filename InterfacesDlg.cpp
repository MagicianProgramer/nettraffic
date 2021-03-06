// CInterfacesDlg.cpp : implementation file
//

#include "stdafx.h"
#include "NetworkTrafficGeneration.h"
#include "InterfacesDlg.h"
#include "afxdialogex.h"
//#include "common.h"
#include "MyPcap.h"


// CInterfacesDlg dialog

IMPLEMENT_DYNAMIC(CInterfacesDlg, CDialogEx)

CInterfacesDlg::CInterfacesDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DLG_INTERFACES, pParent)
{
}

CInterfacesDlg::~CInterfacesDlg()
{
}

void CInterfacesDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_ADAPTER, m_listCtrlAdapters);
}


BEGIN_MESSAGE_MAP(CInterfacesDlg, CDialogEx)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_ADAPTER, &CInterfacesDlg::OnLvnItemchangedListAdapter)
	ON_BN_CLICKED(IDOK, &CInterfacesDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CInterfacesDlg message handlers


void CInterfacesDlg::OnLvnItemchangedListAdapter(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: Add your control notification handler code here
	m_nSel = pNMLV->iItem;
	*pResult = 0;
}


void CInterfacesDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	if (m_nSel < 0)
	{
		AfxMessageBox(L"Please select network adapter.");
		return;
	}

	CMyPcap* pCap = (CMyPcap*)m_lpCap;
	pCap->SelectAdapter(m_nSel);

	CDialogEx::OnOK();
}


BOOL CInterfacesDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  Add extra initialization here
	//init list//
	m_listCtrlAdapters.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP);
	m_listCtrlAdapters.ModifyStyle(LVS_TYPEMASK, LVS_REPORT);
	m_listCtrlAdapters.InsertColumn(0, L"Name", LVCFMT_LEFT, 200);
	m_listCtrlAdapters.InsertColumn(1, L"Address", LVCFMT_LEFT, 150);

	//get network adapters//
	GetAdaptersAndInsert();

	m_nSel = -1;

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CInterfacesDlg::SetPcapPoint(LPVOID lParam)
{
	m_lpCap = lParam;
}

void CInterfacesDlg::GetAdaptersAndInsert()
{
	CMyPcap* pCap = (CMyPcap*)m_lpCap;

	pCap->GetNetAdaptersAndInit();//this function gets net adapter list
							//this is in 'common.h'
	for (int i = 0; i < pCap->m_nAdapterCount; i++)
	{
		wchar_t wsztmp[250];

		//insert//
		int n = m_listCtrlAdapters.GetItemCount();
		ConvertA2W(pCap->m_devices[i].description, wsztmp);
		m_listCtrlAdapters.InsertItem(n, wsztmp);
		ConvertA2W(inet_ntoa(((struct sockaddr_in *)pCap->m_devices[i].addresses->addr)->sin_addr), wsztmp);
		m_listCtrlAdapters.SetItemText(n, 1, wsztmp);
	}
}