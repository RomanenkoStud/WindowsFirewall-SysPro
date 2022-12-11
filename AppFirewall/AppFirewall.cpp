// AppFirewall.cpp : Определяет точку входа для приложения.
//

#include "framework.h"
#include "AppFirewall.h"

#define MAX_LOADSTRING 100

// Глобальные переменные:
HINSTANCE hInst;                                // текущий экземпляр
WCHAR szTitle[MAX_LOADSTRING];                  // Текст строки заголовка
WCHAR szWindowClass[MAX_LOADSTRING];            // имя класса главного окна
HWND listOfRules;
HWND hStart, hStop, hAdd, hDelete, hInstall, hUninstall, hTest;
UDriver ipDrvFirewall;

WCHAR columnsTitle[6][20] = { L"sourceIp",L"sourcePort", L"destinationIp", 
                                L"destinationPort", L"protocol", L"action" };
WCHAR   prt[3][20] = { L"ICMP", L"IP", L"TCP" };
WCHAR   act[2][20] = { L"FORWARD", L"DROP" };

// Отправить объявления функций, включенных в этот модуль кода:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Add(HWND, UINT, WPARAM, LPARAM);
void                InitControls(HWND);
BOOL                VerifyIP(WCHAR*);
DWORD               AddFilter(IPFilter);
void                Install();
void                Uninstall();
void                AddBlock();

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Разместите код здесь.

    // Инициализация глобальных строк
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_APPFIREWALL, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Выполнить инициализацию приложения:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_APPFIREWALL));

    MSG msg;

    // Цикл основного сообщения:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

//
//  ФУНКЦИЯ: MyRegisterClass()
//
//  ЦЕЛЬ: Регистрирует класс окна.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPFIREWALL));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_APPFIREWALL);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   ФУНКЦИЯ: InitInstance(HINSTANCE, int)
//
//   ЦЕЛЬ: Сохраняет маркер экземпляра и создает главное окно
//
//   КОММЕНТАРИИ:
//
//        В этой функции маркер экземпляра сохраняется в глобальной переменной, а также
//        создается и выводится главное окно программы.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Сохранить маркер экземпляра в глобальной переменной

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, CW_USEDEFAULT, 635, 430, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  ФУНКЦИЯ: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  ЦЕЛЬ: Обрабатывает сообщения в главном окне.
//
//  WM_COMMAND  - обработать меню приложения
//  WM_PAINT    - Отрисовка главного окна
//  WM_DESTROY  - отправить сообщение о выходе и вернуться
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        InitControls(hWnd);
        int code = 0;
        //we load the IPFilter Driver
        code = ipDrvFirewall.LoadDriver(L"WfpDrvFirewall", NULL, NULL, TRUE);
        if (code != DRV_SUCCESS)
        {
            WCHAR str[100];
            swprintf_s(str, L"ERROR %d init DrvFirewall. Run the application with admin privilages", code);
            MessageBoxW(hWnd, str, NULL, MB_OK);
            DestroyWindow(hWnd);
        }
    }
    break;

    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Разобрать выбор в меню:
            switch (wmId)
            {
            case IDB_START:
                if (ipDrvFirewall.WriteIo(START_IP_HOOK, NULL, 0) != DRV_ERROR_IO)
                {
                    EnableWindow(hStart, false);
                    EnableWindow(hStop, true);
                }
                break;
            case IDB_STOP:
                if (ipDrvFirewall.WriteIo(STOP_IP_HOOK, NULL, 0) != DRV_ERROR_IO)
                {
                    EnableWindow(hStart, true);
                    EnableWindow(hStop, false);
                }
                break;
            case IDB_ADD:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ADD), hWnd, Add);
                break;
            case IDB_DELETE:
                if (ipDrvFirewall.WriteIo(CLEAR_FILTER, NULL, 0) != DRV_ERROR_IO)
                {
                    MessageBoxW(hWnd, L"Rules list is clear", NULL, MB_OK);
                    SendMessage(listOfRules, LVM_DELETEALLITEMS, 0, 0);
                }
                break;
            case IDB_INSTALL:
                ipDrvFirewall.StartDriver();
                Install();
                break;
            case IDB_UNINSTALL:
                ipDrvFirewall.StopDriver();
                Uninstall();
                break;
            case IDB_TEST:
                AddBlock();
                break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Добавьте сюда любой код прорисовки, использующий HDC...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Обработчик сообщений для окна "О программе".
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

INT_PTR CALLBACK Add(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        SendMessage(GetDlgItem(hDlg, IDC_COMBO1), (UINT)CB_ADDSTRING, (WPARAM)0, (LPARAM)prt[0]);
        SendMessage(GetDlgItem(hDlg, IDC_COMBO1), (UINT)CB_ADDSTRING, (WPARAM)0, (LPARAM)prt[1]);
        SendMessage(GetDlgItem(hDlg, IDC_COMBO1), (UINT)CB_ADDSTRING, (WPARAM)0, (LPARAM)prt[2]);
        SendMessage(GetDlgItem(hDlg, IDC_COMBO1), CB_SETCURSEL, (WPARAM)0, (LPARAM)0);

        SendMessage(GetDlgItem(hDlg, IDC_COMBO2), (UINT)CB_ADDSTRING, (WPARAM)0, (LPARAM)act[0]);
        SendMessage(GetDlgItem(hDlg, IDC_COMBO2), (UINT)CB_ADDSTRING, (WPARAM)0, (LPARAM)act[1]);
        SendMessage(GetDlgItem(hDlg, IDC_COMBO2), CB_SETCURSEL, (WPARAM)0, (LPARAM)0);

        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_CLOSE || LOWORD(wParam) == WM_DESTROY)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        else if (LOWORD(wParam) == ID_ADD)
        {
            BOOL	setact;
            int		setproto;
            WCHAR   destIp[20], destPort[20], sourceIp[20], sourcePort[20];
            int action = SendMessage((HWND)GetDlgItem(hDlg, IDC_COMBO2), (UINT)CB_GETCURSEL,
                (WPARAM)0, (LPARAM)0);

            if (action == 0)
                setact = FALSE;
            else
                setact = TRUE;

            int proto = SendMessage((HWND)GetDlgItem(hDlg, IDC_COMBO1), (UINT)CB_GETCURSEL,
                (WPARAM)0, (LPARAM)0);
            if (proto == 0)
                setproto = 1;
            if (proto == 1)
                setproto = 17;
            if (proto == 2)
                setproto = 6;

            GetDlgItemText(hDlg, IDC_EDIT2, (LPWSTR)&destIp, 20);
            GetDlgItemText(hDlg, IDC_EDIT3, (LPWSTR)&destPort, 20);
            GetDlgItemText(hDlg, IDC_EDIT1, (LPWSTR)&sourceIp, 20);
            GetDlgItemText(hDlg, IDC_EDIT4, (LPWSTR)&sourcePort, 20);
            if (!(VerifyIP(destIp) && VerifyIP(sourceIp))) 
            {
                MessageBoxW(hDlg, L"Invalid IP adress", NULL, MB_OK);
                break;
            }
            IPFilter   ip;
            char c[20];
            size_t charsConverted = 0;
            InetPtonW(AF_INET, destIp, &ip.destinationIp);
            ip.destinationIp = ntohl(ip.destinationIp);
            ip.destinationPort = _wtoi(destPort);
            InetPtonW(AF_INET, sourceIp, &ip.sourceIp);
            ip.sourceIp = ntohl(ip.sourceIp);
            ip.sourcePort = _wtoi(sourcePort);
            ip.protocol = setproto;
            ip.drop = setact;

            DWORD result = AddFilter(ip);

            LVITEM lvI;
            lvI.mask = LVIF_TEXT;
            lvI.iItem = 0;
            lvI.iSubItem = 0;
            lvI.pszText = (LPWSTR)sourceIp;
            ListView_InsertItem(listOfRules, &lvI);

            lvI.iSubItem = 1;
            lvI.pszText = (LPWSTR)sourcePort;
            ListView_SetItem(listOfRules, &lvI);

            lvI.iSubItem = 2;
            lvI.pszText = (LPWSTR)destIp;
            ListView_SetItem(listOfRules, &lvI);

            lvI.iSubItem = 3;
            lvI.pszText = (LPWSTR)destPort;
            ListView_SetItem(listOfRules, &lvI);

            lvI.iSubItem = 4;
            lvI.pszText = (LPWSTR)prt[proto];
            ListView_SetItem(listOfRules, &lvI);

            lvI.iSubItem = 5;
            lvI.pszText = (LPWSTR)act[action];
            ListView_SetItem(listOfRules, &lvI);

            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

void InitControls(HWND hWnd)
{
    hStart = CreateWindowW(L"BUTTON", L"Start",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_TEXT,
        10, 10, 60, 30, hWnd, (HMENU)IDB_START, hInst, NULL);
    hStop = CreateWindowW(L"BUTTON", L"Stop",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_TEXT | WS_DISABLED,
        70, 10, 60, 30, hWnd, (HMENU)IDB_STOP, hInst, NULL);
    hAdd = CreateWindowW(L"BUTTON", L"Add",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_TEXT,
        130, 10, 60, 30, hWnd, (HMENU)IDB_ADD, hInst, NULL);
    hDelete = CreateWindowW(L"BUTTON", L"Delete",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_TEXT,
        190, 10, 60, 30, hWnd, (HMENU)IDB_DELETE, hInst, NULL);
    hInstall = CreateWindowW(L"BUTTON", L"Install",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_TEXT | WS_DISABLED,
        250, 10, 60, 30, hWnd, (HMENU)IDB_INSTALL, hInst, NULL);
    hUninstall = CreateWindowW(L"BUTTON", L"Uninstall",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_TEXT,
        310, 10, 60, 30, hWnd, (HMENU)IDB_UNINSTALL, hInst, NULL);
    hTest = CreateWindowW(L"BUTTON", L"TEST",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_TEXT,
        550, 10, 60, 30, hWnd, (HMENU)IDB_TEST, hInst, NULL);

    INITCOMMONCONTROLSEX icex;
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);
    listOfRules = CreateWindowW(L"SysListView32", L"",
        WS_VISIBLE | WS_BORDER | WS_CHILD | LVS_REPORT | LVS_EDITLABELS,
        10, 50, 600, 300,
        hWnd, (HMENU)ID_LIST, hInst, 0);

    for (int i = 0; i < 6; i++)
    {
        LVCOLUMN lvc;
        lvc.iSubItem = 0;
        lvc.pszText = (LPWSTR)columnsTitle[i];
        lvc.cx = 100;
        lvc.fmt = LVCFMT_LEFT;
        lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
        ListView_InsertColumn(listOfRules, i, &lvc);
    }
}

BOOL VerifyIP(WCHAR* wstr)
{
    int pos = 0, prevpos = -1;		
    CString    str = wstr;
    CString    str1;

    if (str.Find('.') == -1)
        return FALSE;

    if (str.FindOneOf(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != -1)
        return FALSE;

    if (str.FindOneOf(L"!@#$%^&*()_+|-;:'\"/?><,") != -1)
        return FALSE;

    int _pos = 0;
    _pos = str.Find('.');
    if ((0 > _pos) || (_pos > 3))
        return FALSE;
    int newpos = _pos;
    _pos = str.Find('.', _pos + 1);
    if ((newpos + 1 >= _pos) || (_pos > newpos + 4))
        return FALSE;
    newpos = _pos;
    _pos = str.Find('.', _pos + 1);
    if ((newpos + 1 >= _pos) || (_pos > newpos + 4))
        return FALSE;

    for (int cnt = 0; cnt <= 3; cnt++)
    {
        if (cnt < 3)
            pos = str.Find('.', pos + 1);
        else
            pos = str.GetLength();
        str1 = str.Left(pos);
        char ch[30];

        str1 = str1.Right(pos - (prevpos + 1));
        unsigned int a = _wtoi(str1);
        if ((0 > a) || (a > 255))
        {
            return FALSE;
        }
        prevpos = pos;
    }
    return TRUE;

}

DWORD AddFilter(IPFilter pf)
{
    DWORD result = ipDrvFirewall.WriteIo(ADD_FILTER, &pf, sizeof(pf));

    if (result != DRV_SUCCESS)
        return FALSE;
    else
        return TRUE;
}

void Install()
{
    EnableWindow(hStart, true);
    EnableWindow(hStop, false);
    EnableWindow(hAdd, true);
    EnableWindow(hDelete, true);
    EnableWindow(hUninstall, true);
    EnableWindow(hInstall, false);
    EnableWindow(hTest, true);
}

void Uninstall() 
{
    EnableWindow(hStart, false);
    EnableWindow(hStop, false);
    EnableWindow(hAdd, false);
    EnableWindow(hDelete, false);
    EnableWindow(hUninstall, false);
    EnableWindow(hInstall, true);
    EnableWindow(hTest, false);
    SendMessage(listOfRules, LVM_DELETEALLITEMS, 0, 0);
}

void AddBlock()
{
    IPFilter   ip;
    ip.destinationIp = 0;
    ip.destinationPort = 0;
    ip.sourceIp = 0;
    ip.sourcePort = 0;
    ip.protocol = 0;
    ip.drop = TRUE;

    AddFilter(ip);

    LVITEM lvI;
    lvI.mask = LVIF_TEXT;
    lvI.iItem = 0;
    lvI.iSubItem = 0;
    lvI.pszText = (LPWSTR)L"ALL";
    ListView_InsertItem(listOfRules, &lvI);

    lvI.iSubItem = 1;
    lvI.pszText = (LPWSTR)L"ALL";
    ListView_SetItem(listOfRules, &lvI);

    lvI.iSubItem = 2;
    lvI.pszText = (LPWSTR)L"ALL";
    ListView_SetItem(listOfRules, &lvI);

    lvI.iSubItem = 3;
    lvI.pszText = (LPWSTR)L"ALL";
    ListView_SetItem(listOfRules, &lvI);

    lvI.iSubItem = 4;
    lvI.pszText = (LPWSTR)L"ALL";
    ListView_SetItem(listOfRules, &lvI);

    lvI.iSubItem = 5;
    lvI.pszText = (LPWSTR)L"DROP";
    ListView_SetItem(listOfRules, &lvI);
}