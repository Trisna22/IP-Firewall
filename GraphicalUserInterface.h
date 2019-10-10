#pragma once

#include "stdafx.h"
#include "Resources.h"
#include "IPFirewall.h"
#include "XMLWriter.h"
#include "XMLReader.h"
#include "RuleHandling.h"

namespace GraphicalUserInterface
{
	HWND HwndMainWindow = NULL;
	IPFirewall firewall;

	bool RegisterWindowClass(HINSTANCE);
	bool CreateMainWindow(HINSTANCE, int);

	void InitializeWindowComponents(HWND);

	LRESULT CALLBACK MainWindowProcess(HWND, UINT, WPARAM, LPARAM);

	string GetText(HWND);
	LRESULT CustomDrawListview(NMLVCUSTOMDRAW*, LPARAM, HWND);
	void GiveButtonColor(LPNMCUSTOMDRAW, COLORREF, COLORREF);
	HBRUSH CreateGradientBrush(COLORREF, COLORREF, LPNMCUSTOMDRAW);

	void AddRulesToListbox(HWND);
}

/*   Creating windows by registering and call the CreateWindow function.   */
bool GraphicalUserInterface::RegisterWindowClass(HINSTANCE hInstance)
{
	WNDCLASSEX wc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = GraphicalUserInterface::MainWindowProcess;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadIcon(NULL, IDC_HAND);
	wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
	wc.lpszMenuName = WindowTitleName;
	wc.lpszClassName = WindowClassName;
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	if (!RegisterClassEx(&wc))
	{
		MessageBoxA(NULL, "Window registration failed!", "IF: Error", MB_OK | MB_ICONERROR);
		return false;
	}
	return true;
}
bool GraphicalUserInterface::CreateMainWindow(HINSTANCE hInstance, int nCmdShow)
{
	HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, WindowClassName, WindowTitleName,
		WS_OVERLAPPEDWINDOW | WS_BORDER, 100, 50, 800, 650,
		NULL, NULL, hInstance, NULL);
	if (hwnd == NULL)
	{
		MessageBoxA(NULL, "Failed to create a window!", "IPS: Error", MB_OK | MB_ICONERROR);
		return false;
	}
	
	HwndMainWindow = hwnd;
	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);
	return true;
}

/*   Creates the interactive controls in the main window.   */
void GraphicalUserInterface::InitializeWindowComponents(HWND hwndParent)
{
	//	Global variables to use.
	HINSTANCE hInstance = (HINSTANCE)GetWindowLong(hwndParent, GWL_HINSTANCE);
	HFONT defaultFont = CreateFontA(20, 0, FW_DONTCARE, FALSE, FW_MEDIUM, FALSE, FALSE, FALSE,
		ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
		DEFAULT_PITCH | FF_SWISS, "Consolas");
	HFONT ListviewFONT = CreateFontA(22, 0, FW_DONTCARE, FALSE, FW_MEDIUM, FALSE, FALSE, FALSE,
		ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
		DEFAULT_PITCH | FF_SWISS, "Consolas");

	/*   Creating controls for window.   */

	HWND label1 = CreateWindowEx(WS_EX_TRANSPARENT, "STATIC", "Status: ",
		WS_CHILD | WS_SYSMENU | WS_VISIBLE | SS_LEFT,
		50, 30, 100, 30,
		hwndParent, (HMENU)0, hInstance, 0);
	SendMessage(label1, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);

	HWND label2 = CreateWindowEx(WS_EX_TRANSPARENT, "STATIC", "Firewall offline",
		WS_CHILD | WS_SYSMENU | WS_VISIBLE | SS_LEFT,
		120, 30, 300, 30,
		hwndParent, (HMENU)LABEL_STATUS2, hInstance, 0);
	SendMessage(label2, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);

	HWND label3 = CreateWindowEx(WS_EX_TRANSPARENT, "STATIC", "Blocked IP addresses:",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT | WS_BORDER,
		30, 80, 450, 30, 
		hwndParent, (HMENU)0, hInstance, 0);
	SendMessage(label3, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);

	HWND listview = CreateWindow("listbox", NULL, 
		LBS_STANDARD | LBS_SORT | WS_TABSTOP | WS_BORDER | WS_CHILD | WS_VISIBLE,
		30, 140, 500, 400, 
		hwndParent, (HMENU)LISTVIEW_IP, hInstance, 0);
	SendMessage(listview, WM_SETFONT, (WPARAM)ListviewFONT, (LPARAM)TRUE);
	SendMessage(listview, LVM_SETBKCOLOR, (WPARAM)NULL, (LPARAM)RGB(0, 0, 0));

	HWND label4 = CreateWindowEx(WS_EX_TRANSPARENT, "STATIC", "Rule to add:",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		550, 150, 200, 30,
		hwndParent, (HMENU)0, hInstance, 0);
	SendMessage(label4, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);

	HWND ipinput = CreateWindowEx(WS_EX_TRANSPARENT, WC_IPADDRESS, "",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		550, 190, 200, 24,
		hwndParent, (HMENU)INPUT_IPADDR, hInstance, 0);
	SendMessage(ipinput, WM_SETFONT, (WPARAM)ListviewFONT, (LPARAM)TRUE);

	HWND button = CreateWindow("BUTTON", "Add IP rule",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | BS_PUSHBUTTON,
		550, 230, 200, 30, hwndParent,
		(HMENU)BUTTON_ADDRULES, hInstance, 0);
	SendMessage(button, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);

	HWND button2 = CreateWindow("BUTTON", "Start Firewall",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | BS_PUSHBUTTON,
		550, 50, 200, 30, hwndParent,
		(HMENU)BUTTON_FWSWITCH, hInstance, 0);
	SendMessage(button2, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);

	HWND label5 = CreateWindowEx(WS_EX_TRANSPARENT, "STATIC", "Rule to delete:",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		550, 300, 200, 30,
		hwndParent, (HMENU)0, hInstance, 0);
	SendMessage(label5, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);

	HWND label_selected = CreateWindowEx(WS_EX_TRANSPARENT, "STATIC", "NONE_SELECTED",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		550, 340, 200, 30,
		hwndParent, (HMENU)LABEL_SELECTEDIP, hInstance, 0);
	SendMessage(label_selected, WM_SETFONT, (WPARAM)ListviewFONT, (LPARAM)TRUE);

	HWND button3 = CreateWindow("BUTTON", "Delete IP rule",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		550, 380, 200, 30,
		hwndParent, (HMENU)BUTTON_DELETERULE, hInstance, 0);
	SendMessage(button3, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);

	HWND button4 = CreateWindow("BUTTON", "Copyrights software",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		550, 550, 200, 30,
		hwndParent, (HMENU)BUTTON_COPYRIGHTS, hInstance, 0);
	SendMessage(button4, WM_SETFONT, (WPARAM)defaultFont, (LPARAM)TRUE);
}

/*   The message loop that runs forever.   */
LRESULT CALLBACK GraphicalUserInterface::MainWindowProcess(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{ 
	HINSTANCE hInstance = (HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE);
	switch (msg)
	{
	case WM_CREATE:
	{
		InitializeWindowComponents(hwnd);
		break;
	}
	case WM_NCCREATE:
	{

		AddRulesToListbox(hwnd);
		break;
	}
	case WM_COMMAND:
	{
		if (LOWORD(wParam) == BUTTON_ADDRULES && HIWORD(wParam) == BN_CLICKED)
		{
			string env = getenv("ProgramFiles");
			string path = env + "\\IP Firewall\\Profile_" + firewall.WIFI_SSID + ".config";

			RuleHandler handler(path);
			if (!handler.IsReady())
			{
				MessageBox(0, "Failed to add IP, RuleHandler not ready!", "IF: Warning", MB_OK | MB_ICONERROR);
				break;
			}

			string IP = GetText(GetDlgItem(hwnd, INPUT_IPADDR));

			if (handler.AddRule(IP) == true)
			{
				SetWindowText(GetDlgItem(hwnd, INPUT_IPADDR), "");
				MessageBox(0, "IP succesfully added to list!", "IF: Warning", MB_OK | MB_ICONWARNING);
			}

			AddRulesToListbox(hwnd);

			break;
		}
		if (LOWORD(wParam) == BUTTON_DELETERULE && HIWORD(wParam) == BN_CLICKED)
		{
			string env = getenv("ProgramFiles");
			string path = env + "\\IP Firewall\\Profile_" + firewall.WIFI_SSID + ".config";

			RuleHandler handler(path);
			if (!handler.IsReady())
			{
				MessageBox(0, "Failed to delete rule, RuleHandler not ready!", "IF: Error", MB_OK | MB_ICONERROR);
				break;
			}

			string IP = GetText(GetDlgItem(hwnd, LABEL_SELECTEDIP));

			if (handler.DeleteRule(IP) == false)
			{
				MessageBox(0, "Failed to delete the selected IP address!", "IF: Warning", MB_OK | MB_ICONWARNING);
			}
			else
			{
				SetWindowText(GetDlgItem(hwnd, LABEL_SELECTEDIP), "                              ");
				SetWindowText(GetDlgItem(hwnd, LABEL_SELECTEDIP), "NONE_SELECTED");
				MessageBox(0, "Succesfully deleted the selected IP address!", "IF: Warning", MB_OK | MB_ICONINFORMATION);
			}
			
			AddRulesToListbox(hwnd);
			break;
		}
		if (LOWORD(wParam) == BUTTON_FWSWITCH && HIWORD(wParam) == BN_CLICKED)
		{
			if (firewall.IsFirewallRunning == false)
			{
				if (firewall.StartFirewall(GetDlgItem(hwnd, LISTVIEW_IP)) == false)
					MessageBox(0, "Failed to start the firewall!", "IF: Error", MB_OK | MB_ICONERROR);
				else
				{
					SetWindowText(GetDlgItem(hwnd, BUTTON_FWSWITCH), "Stop Firewall"); 
					SetWindowText(GetDlgItem(hwnd, LABEL_STATUS2), "Firewall online ");
				}
			}
			else
			{
				if (firewall.StopFirewall() == false)
					MessageBox(0, "Failed to stop the firewall!", "IF: Error", MB_OK | MB_ICONERROR);
				else
				{
					SetWindowText(GetDlgItem(hwnd, BUTTON_FWSWITCH), "Start Firewall");
					SetWindowText(GetDlgItem(hwnd, LABEL_STATUS2), "Firewall offline ");
					MessageBox(0, "IP Firewall stopped!\n( Not recommended! )", "IF: Info", MB_OK | MB_ICONINFORMATION);
				}
			}
			break;
		}
		if (LOWORD(wParam) == BUTTON_COPYRIGHTS && HIWORD(wParam) == BN_CLICKED)
		{
			MessageBox(hwnd, "Project name:\t\t\tIP Firewall\n"
				"Author:\t\t\t\tTrisna Quebe\n"
				"Creation date:\t\t\t7-10-2019\n\n"
				"Copyrights (c) 2019-2020 Trisna Quebe all rights served.", "IF: Copyrights", MB_OK | MB_ICONWARNING);
			break;
		}
		if (LOWORD(wParam) == LISTVIEW_IP && HIWORD(wParam) == LBN_SELCHANGE)
		{
			int ItemPosition = (int)SendMessage(GetDlgItem(hwnd, LISTVIEW_IP), LB_GETCURSEL, 0, 0);

			int ItemLength = (int)SendMessage(GetDlgItem(hwnd, LISTVIEW_IP), LB_GETTEXTLEN, ItemPosition, 0);

			char *buffer = new char[ItemLength];
			SendMessage(GetDlgItem(hwnd, LISTVIEW_IP), LB_GETTEXT, (WPARAM)ItemPosition, (LPARAM)buffer);

			string str = buffer;
			SetWindowText(GetDlgItem(hwnd, LABEL_SELECTEDIP), "                              ");
			SetWindowText(GetDlgItem(hwnd, LABEL_SELECTEDIP), str.c_str());
			break;
		}
		break;
	}
	case WM_NOTIFY:
	{
		NMHDR* Item = (NMHDR*)lParam;
		
		if (Item->idFrom == LISTVIEW_IP && Item->code == NM_CUSTOMDRAW)
		{
			return CustomDrawListview((NMLVCUSTOMDRAW*)Item, lParam, GetDlgItem(hwnd, LISTVIEW_IP));
		}

		if (Item->idFrom == BUTTON_ADDRULES)
		{
			MessageBoxA(NULL, "TEST", "TEST", MB_OK);
			LPNMCUSTOMDRAW BTN = (LPNMCUSTOMDRAW)Item;
			GiveButtonColor(BTN, RGB(38, 77, 115), RGB(51, 102, 153));
			return CDRF_DODEFAULT;
		}

		if (Item->idFrom == BUTTON_FWSWITCH)
		{
			MessageBoxA(NULL, "TEST", "TEST", MB_OK);
			LPNMCUSTOMDRAW BTN = (LPNMCUSTOMDRAW)Item;
			GiveButtonColor(BTN, RGB(204, 0, 0), RGB(230, 57, 0));
			return CDRF_DODEFAULT;
		}

		return CDRF_DODEFAULT;
	}
	case WM_CTLCOLORBTN:
	{
		return (LRESULT)GetSysColorBrush(COLOR_WINDOW + 1);
	}
	case WM_CTLCOLORSTATIC:
	{
		DWORD ID = GetDlgCtrlID((HWND)lParam);
		if (ID == LABEL_STATUS2)
		{
			string str = GetText(GetDlgItem(hwnd, LABEL_STATUS2));
			if (str == "Firewall offline" || str.find("Error") != string::npos || str.find("offline") != string::npos)
			{
				HDC hdc = reinterpret_cast<HDC>(wParam);
				SetTextColor(hdc, RGB(255, 0, 0));
				SetBkColor(hdc, TRANSPARENT);
				return (LONG)GetStockObject(NULL_BRUSH);
			}
			else if (str == "Firewall online" || str.find("online") != string::npos)
			{
				HDC hdc = reinterpret_cast<HDC>(wParam);
				SetTextColor(hdc, RGB(47, 212, 69));
				SetBkColor(hdc, TRANSPARENT);
				return (LONG)GetStockObject(NULL_BRUSH);
			}
			else
			{
				HDC hdc = reinterpret_cast<HDC>(wParam);
				SetTextColor(hdc, RGB(221, 226, 106));
				SetBkColor(hdc, TRANSPARENT);
				return (LONG)GetStockObject(NULL_BRUSH);
			}
		}
		else if (ID == LABEL_SELECTEDIP)
		{
			string str = GetText(GetDlgItem(hwnd, LABEL_SELECTEDIP));
			if (str == "NONE_SELECTED")
			{
				HDC hdc = reinterpret_cast<HDC>(wParam);
				SetTextColor(hdc, RGB(221, 226, 106));
				SetBkColor(hdc, TRANSPARENT);
				return (LONG)GetStockObject(NULL_BRUSH);
			}
			else
			{
				HDC hdc = reinterpret_cast<HDC>(wParam);
				SetTextColor(hdc, RGB(255, 0, 0));
				SetBkColor(hdc, TRANSPARENT);
				return (LONG)GetStockObject(NULL_BRUSH);
			}
		}
		else
		{
			HDC hdc = reinterpret_cast<HDC>(wParam);
			SetTextColor(hdc, RGB(255, 255, 255));
			SetBkColor(hdc, RGB(0, 0, 0));
			return (LONG)GetStockObject(NULL_BRUSH);
		}
		break;
	}
	case WM_CLOSE:
	{
		DestroyWindow(hwnd);
		break;
	}
	case WM_GETMINMAXINFO:
	{
		LPMINMAXINFO lpMMI = (LPMINMAXINFO)lParam;
		lpMMI->ptMinTrackSize.x = 800;
		lpMMI->ptMinTrackSize.y = 650;
		lpMMI->ptMaxTrackSize.x = 800;
		lpMMI->ptMaxTrackSize.y = 650;
		break;
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		break;
	}

	default:
		break;
	}

	return DefWindowProc(hwnd, msg, wParam, lParam);

}

/*   Gets text from any control.   */
string GraphicalUserInterface::GetText(HWND hwndControl)
{
	char buffer[MAX_PATH];
	GetWindowText(hwndControl, buffer, MAX_PATH);
	return (string)buffer;
}

/*   Custom draws the listview we're using in the window.   */
LRESULT GraphicalUserInterface::CustomDrawListview(NMLVCUSTOMDRAW* pcd, LPARAM lParam, HWND Listview)
{
	LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;
	TCHAR buffer[16];
	LVITEM item;
	WCHAR ItemText[64];

	switch (pcd->nmcd.dwDrawStage)
	{
	case CDDS_PREPAINT:
	{
		/* Tell the control we are interested in per-item notifications.*/
		return CDRF_DODEFAULT | CDRF_NOTIFYITEMDRAW;
	}
	case (CDDS_ITEM | CDDS_PREPAINT):
	{
		lplvcd->clrText = RGB(255, 255, 255);
		lplvcd->clrTextBk = RGB(0, 0, 0);
		return CDRF_DODEFAULT;
	}
	}
	return CDRF_DODEFAULT;
}

/*   Give the buttons in window a hover color and a default color.   */
void GraphicalUserInterface::GiveButtonColor(LPNMCUSTOMDRAW BTN, COLORREF HoverColor, COLORREF defaultColor)
{
	if (BTN->uItemState & CDIS_HOT)
	{
		//	Select our hot BRUSH color
		HBRUSH hotBRUSH = CreateGradientBrush(HoverColor, HoverColor, BTN);

		HPEN pen = CreatePen(PS_INSIDEFRAME, 0, RGB(0, 0, 0));

		HGDIOBJ old_pen = SelectObject(BTN->hdc, pen);
		HGDIOBJ old_brush = SelectObject(BTN->hdc, hotBRUSH);

		RoundRect(BTN->hdc, BTN->rc.left, BTN->rc.top, BTN->rc.right, BTN->rc.bottom, 5, 5);

		SelectObject(BTN->hdc, old_pen);
		SelectObject(BTN->hdc, old_brush);
		DeleteObject(pen);
	}
	else
	{
		//	Select our default BRUSH color
		HBRUSH defaultBRUSH = CreateGradientBrush(defaultColor, defaultColor, BTN);

		HPEN pen = CreatePen(PS_INSIDEFRAME, 0, RGB(0, 0, 0));

		HGDIOBJ old_pen = SelectObject(BTN->hdc, pen);
		HGDIOBJ old_brush = SelectObject(BTN->hdc, defaultBRUSH);

		RoundRect(BTN->hdc, BTN->rc.left, BTN->rc.top, BTN->rc.right, BTN->rc.bottom, 5, 5);

		SelectObject(BTN->hdc, old_pen);
		SelectObject(BTN->hdc, old_brush);
		DeleteObject(pen);
	}
}
HBRUSH GraphicalUserInterface::CreateGradientBrush(COLORREF top, COLORREF bottom, LPNMCUSTOMDRAW item)
{
	HBRUSH Brush = NULL;
	HDC hdcmem = CreateCompatibleDC(item->hdc);
	HBITMAP hbitmap = CreateCompatibleBitmap(item->hdc, item->rc.right - item->rc.left, item->rc.bottom - item->rc.top);
	SelectObject(hdcmem, hbitmap);

	int r1 = GetRValue(top), r2 = GetRValue(bottom), g1 = GetGValue(top), g2 = GetGValue(bottom), b1 = GetBValue(top), b2 = GetBValue(bottom);
	for (int i = 0; i < item->rc.bottom - item->rc.top; i++)
	{
		RECT temp;
		int r, g, b;
		r = int(r1 + double(i * (r2 - r1) / item->rc.bottom - item->rc.top));
		g = int(g1 + double(i * (g2 - g1) / item->rc.bottom - item->rc.top));
		b = int(b1 + double(i * (b2 - b1) / item->rc.bottom - item->rc.top));
		Brush = CreateSolidBrush(RGB(r, g, b));
		temp.left = 0;
		temp.top = i;
		temp.right = item->rc.right - item->rc.left;
		temp.bottom = i + 1;
		FillRect(hdcmem, &temp, Brush);
		DeleteObject(Brush);
	}
	HBRUSH pattern = CreatePatternBrush(hbitmap);

	DeleteDC(hdcmem);
	DeleteObject(Brush);
	DeleteObject(hbitmap);

	return pattern;
}

/*   Adds the rules in the .config files to the listbox.   */
void GraphicalUserInterface::AddRulesToListbox(HWND hwnd)
{
	SendMessage(GetDlgItem(hwnd, LISTVIEW_IP), LB_RESETCONTENT, 0, 0);

	string env = getenv("ProgramFiles");
	string path = env + "\\IP Firewall\\Profile_" + firewall.WIFI_SSID + ".config";

	XMLReader reader(path);
	if (!reader.IsReady())
	{
		string msg = "Failed to open the configuration file for this wifi setting! Error code: " + to_string(GetLastError());
		MessageBox(0, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return;
	}

	//	List trough IP addresses and add them to the list.
	for (int i = 0; i < reader.RetrieveIPAddressesInFile(); i++)
	{
		string IP = reader.RetrieveIP(i);
		if (IP == "IP_NOT_FOUND")
			continue;

		SendMessage(GetDlgItem(hwnd, LISTVIEW_IP), LB_ADDSTRING, 0, (LPARAM)IP.c_str());
	}
}