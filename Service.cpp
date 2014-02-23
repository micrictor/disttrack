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
#include "Service.h"
#include "5.h"

namespace sc { namespace service {

VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    // Fill in the SERVICE_STATUS structure.
    dwSvcStatus.dwCurrentState  = dwCurrentState;
    dwSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    dwSvcStatus.dwWaitHint      = dwWaitHint;

    if(dwCurrentState == SERVICE_START_PENDING)
        dwSvcStatus.dwControlsAccepted = 0;
    else
		dwSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if(dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED)
        dwSvcStatus.dwCheckPoint = 0;
    else
		dwSvcStatus.dwCheckPoint = dwCheckPoint++;

    // Report the status of the service to the SCM.
    SetServiceStatus(hSvcStatusHandle, &dwSvcStatus);
}

VOID WINAPI SvcCtrlHandler(DWORD dwCtrl)
{
	if(dwCtrl == SERVICE_CONTROL_STOP)
	{
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		bSvcStopped = true;
		ReportSvcStatus(dwSvcStatus.dwCurrentState, NO_ERROR, 0);
	}
}

VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	hSvcStatusHandle = RegisterServiceCtrlHandlerW(L"wow32", SvcCtrlHandler);
	if(hSvcStatusHandle)
	{
		dwSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		dwSvcStatus.dwServiceSpecificExitCode = 0;
		
		ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
		ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
		Run(TRUE);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
	}
}

VOID SvcSleep(DWORD dwSeconds)
{
	for(; dwSeconds, !bSvcStopped; --dwSeconds)
		Sleep(1000);
}

}}