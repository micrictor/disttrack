/******************************************************************************************
  Copyright 2013 Christian Roggia

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
******************************************************************************************/

// MODIFIED BY mic.ric.tor
#include "Global\Global.h"

namespace sc { namespace service {

static SERVICE_STATUS dwSvcStatus; /// <-- Service status
static SERVICE_STATUS_HANDLE hSvcStatusHandle; /// <-- Service status handle
static bool bSvcStopped; /// <-- Service has been stopped

VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
VOID WINAPI SvcCtrlHandler(DWORD dwCtrl);
VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv);
VOID SvcSleep(DWORD dwSeconds);

}}