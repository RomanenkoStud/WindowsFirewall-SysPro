#pragma once
#pragma comment(lib, "comctl32.lib")
#define _WIN32_WINNT 0x0500
#pragma comment(lib, "Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include "resource.h"
#include "commctrl.h"
#include "winioctl.h"
#include <atlstr.h>

#include "UDriver.h"
#include "..\WfpDrvFirewall\UserHeader.h"


#define ID_LIST 106
#define IDB_START 107
#define IDB_STOP 108
#define IDB_ADD 109
#define IDB_DELETE 110
#define IDB_INSTALL 111
#define IDB_UNINSTALL 112
#define IDB_TEST 113