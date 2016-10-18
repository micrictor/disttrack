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

enum RESOURCE_KEYS
{
	KEY_PKCS12 = 0,
	KEY_PKCS7  = 1,
	KEY_X509   = 2
};

class CGlobals
{
public:
  static DWORD last_random_number = 0;
  static WCHAR random_exec_name[29][15];
  static char keys[4][4];
  static WCHAR test50;
  static WCHAR test100;

  static FILETIME kernel_creation_time    = {};
  static FILETIME kernel_last_write_time  = {};
  static FILETIME kernel_last_access_time = {};

  static WCHAR windows_directory[40] = {};

  static WCHAR trksrv_name[50];
  static WCHAR trksrv_path[256];
  static DWORD trksrv_id;

  static WCHAR netinit_name[50];
  static WCHAR netinit_path[256];
  static DWORD netinit_id;


  static WCHAR unk_pool[30];
  static WCHAR module_path[MAX_PATH];

  static WCHAR **argv;
  static INT32 argc;
  static RTL_CRITICAL_SECTION critical_section;
  static bool ready_to_attack;


  static DWORD netinit_id;
  static WCHAR netinit_name[50];
};

extern CGlobals Globals;


typedef struct _JOB_PROPERTIES {
	WCHAR ServerName[40];
	bool IsServerNameSet;
	DWORD JobId;
} JOB_PROPERTIES, *PJOB_PROPERTIES;

#endif