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
#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include "StdAfx.h"

/** -------------->> Segment ".data" <<-------------- **/
extern WCHAR g_random_exec_name[29][15];

enum RESOURCE_KEYS
{
	KEY_PKCS12 = 0,
	KEY_PKCS7  = 1,
	KEY_X509   = 2
};

extern char g_keys[4][4];

extern WCHAR g_test50 [6][50];
extern WCHAR g_test100[3][100];


extern FILETIME g_kernel_creation_time;
extern FILETIME g_kernel_last_write_time;

extern WCHAR g_windows_directory[40];

/** ----->> Undeclared <<----- **/
extern WCHAR g_unk_pool[30]; // Unused but allocated
extern WCHAR g_module_path[MAX_PATH]; // Path to self
extern FILETIME g_kernel_last_access_time;
extern WCHAR **g_argv;
extern INT32 g_argc;
extern RTL_CRITICAL_SECTION g_critical_section;
extern bool g_ready_to_attack;
extern DWORD g_svc_id;
extern WCHAR g_svc_name[50];
extern DWORD g_netinit_id;
extern WCHAR g_netinit_name[50];


typedef struct _JOB_PROPERTIES {
	WCHAR ServerName[40];
	bool IsServerNameSet;
	DWORD JobId;
} JOB_PROPERTIES, *PJOB_PROPERTIES;

#endif