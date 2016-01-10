// TSSessions.cpp : Enumerates terminal services sessions, window stations and desktops.
// Written by Aaron Margosis, Microsoft Services
//
/*
THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (C) 2007-2012.  Microsoft Corporation.  All rights reserved.
*/

#include "stdafx.h"
#include "Helpers.h"


bool bShowSD = true;


void ShowObjectName(HANDLE hObj)
{
	char sObjName[2048];
	DWORD nLenNeeded = 0;
	if ( !GetUserObjectInformation(hObj, UOI_NAME, PVOID(sObjName), 2048, &nLenNeeded) )
	{
		ShowError(); //"GetUserObjectInformation (UOI_NAME)");
	}
	else
	{
		_tprintf("%s\n", sObjName );
	}
}

void ShowObjectFlags(HANDLE hObj)
{
	_tprintf("Flags:  ");
	USEROBJECTFLAGS uoFlags{};
	DWORD nLenNeeded = 0;
	if ( !GetUserObjectInformation(hObj, UOI_FLAGS, &uoFlags, sizeof(uoFlags), &nLenNeeded) )
	{
		ShowError(); //"GetUserObjectInformation (UOI_FLAGS)");
	}
	else
	{
		cout << HEX(uoFlags.dwFlags) << "\n";
	}
}

bool SidToString(const PSID pSid, tstring & sSid, tstring & sError)
{
	sSid.clear();
	sError.clear();

	CHeapPtr<TCHAR, CLocalAllocator> pStrSid;
	if (ConvertSidToStringSid(pSid, &pStrSid))
	{
		sSid = pStrSid;
		return true;
	}
	else
	{
		//sError = "ConvertSidToStringSid error: " + SysErrorMessageWithCode();
		sError = SysErrorMessageWithCode();
		return false;
	}
}

bool SecDescriptorToString(const PSECURITY_DESCRIPTOR pSD, tstring & sSDDL, tstring & sError)
{
	sSDDL.clear();
	sError.clear();
	
	SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;

	CHeapPtr<TCHAR, CLocalAllocator> pszSddl;
	if (ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, si, &pszSddl, nullptr))
	{
		sSDDL = pszSddl;
		return true;
	}
	else
	{
		//sError = "ConvertSecurityDescriptorToStringSecurityDescriptor error: " + SysErrorMessageWithCode();
		sError = SysErrorMessageWithCode();
		return false;
	}

}

void ShowObjectSid(HANDLE hObj)
{
	BYTE buf[2048];
	DWORD nLenNeeded = 0 ;
	if ( !GetUserObjectInformation(hObj, UOI_USER_SID, PVOID(buf), 2048, &nLenNeeded ) )
	{
		ShowError(); //"GetUserObjectInformation (UOI_USER_SID)");
	}
	else if (0 == nLenNeeded )
	{
		_tprintf("(No user)\n");
	}
	else
	{
		tstring sSid, sError;
		if (SidToString((PSID)buf, sSid, sError))
			_tprintf("%s\n", sSid.c_str() );
		else
			_tprintf("%s\n", sError.c_str() );
	}
}

void ShowObjectSecurity(HANDLE hObj)
{
	BYTE buf[4096];
	PSECURITY_DESCRIPTOR pSD = PSECURITY_DESCRIPTOR(buf);
	DWORD nLenNeeded = 0;
	SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
	if (GetUserObjectSecurity(hObj, &si, pSD, 4096, &nLenNeeded))
	{
		string sSDDL, sError;
		if (SecDescriptorToString(pSD, sSDDL, sError))
			_tprintf("%s\n", sSDDL.c_str() );
		else
			_tprintf("%s\n", sError.c_str() );
	}
	else
	{
		ShowError(); //"GetUserObjectSecurity");
	}
	_tprintf("\n");
}


BOOL  __stdcall EnumDesktopProc(
   LPSTR lpszDesktop,
   LPARAM lParam
)
{
	UNREFERENCED_PARAMETER(lParam);
	_tprintf("       Desktop:  %s\n", lpszDesktop);
	unique_hdesk hDesk{ OpenDesktop(lpszDesktop, 0, FALSE, MAXIMUM_ALLOWED) };//GENERIC_READ);
	if ( !hDesk )
	{
		ShowError("\tOpenDesktop");
	}
	else
	{
		_tprintf("           SID:  ");
		ShowObjectSid(hDesk.get());
		if (bShowSD)
		{
			_tprintf("            SD:  ");
			ShowObjectSecurity(hDesk.get());
		}
	}
	_tprintf("\n");
	return TRUE;
}


BOOL  __stdcall EnumWindowStationProc(
   LPSTR lpszWindowStation,
   LPARAM lParam
)
{
	UNREFERENCED_PARAMETER(lParam);
	_tprintf("\n    WinSta:  %s\n", lpszWindowStation);
	unique_hwinsta hWS{ OpenWindowStation(lpszWindowStation, FALSE, MAXIMUM_ALLOWED) };
	if ( !hWS )
	{
		ShowError(); //"\tOpenWindowStation");
	}
	else
	{
		_tprintf("            ");
		ShowObjectFlags(hWS.get());
		_tprintf("              SID:  ");
		ShowObjectSid(hWS.get());
		if (bShowSD)
		{
			_tprintf("               SD:  ");
			ShowObjectSecurity(hWS.get());
		}
		_tprintf("\n");
		unique_hwinsta hWS_save{ GetProcessWindowStation() };
		if ( SetProcessWindowStation(hWS.get()) )
		{
			BOOL bEDret = EnumDesktops(hWS.get(), EnumDesktopProc, 0);
			if ( ! bEDret )
			{
				ShowError("\tEnumDesktops");
			}
			SetProcessWindowStation(hWS_save.get());
		}
		else
			ShowError("\tSetProcessWindowStation");
	}

	return TRUE;
}


void ShowCurrentWinStaDesktop()
{
	_tprintf("This process/thread running in:\n"\
		"    Session  ");
	unique_htoken hToken;
	if ( ! OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, hToken.get_address_of()) )
	{
		ShowError(); //"OpenProcessToken");
	}
	else
	{
		DWORD dwSessionID = 0, dwRetLen = 0;
		if ( ! GetTokenInformation(hToken.get(), TokenSessionId, &dwSessionID, sizeof(dwSessionID), &dwRetLen) )
		{
			ShowError(); //"GetTokenInformation");
		}
		else
		{
			cout << dwSessionID << "\n";
		}
	}

	_tprintf("    WinSta   ");
	unique_hwinsta hWS{ GetProcessWindowStation() };
	if ( hWS )
	{
		ShowObjectName(hWS.get());
	}
	else
	{
		ShowError(); //"GetProcessWindowStation");
	}

	_tprintf("    Desktop  ");
	//MSDN says not to close this one
	HDESK hDesk0 = GetThreadDesktop(GetCurrentThreadId());
	if ( hDesk0 )
	{
		ShowObjectName(hDesk0);
	}
	else
	{
		ShowError(); //"GetThreadDesktop");
	}

	_tprintf("\nCurrent user input Desktop:  ");
	unique_hdesk hDesk1{ OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED) };
	if ( hDesk1 )
	{
		ShowObjectName(hDesk1.get());
	}
	else
	{
		ShowError(); //"OpenInputDesktop");
	}

	_tprintf("\n");
}


void EnumSessions()
{
	CHeapPtr<WTS_SESSION_INFOA, CWTSAllocator> pSessInfo;
	DWORD dwSessCount = 0;
	BOOL ret = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessInfo, &dwSessCount);
	if ( ! ret )
	{
		tstring sysErrMsg = SysErrorMessageWithCode();
		//cout << "WTSEnumerateSessions failed:  " << sysErrMsg << "\n";
		_tprintf("%s\n", sysErrMsg.c_str());
	}
	else
	{
		_tprintf("Terminal Sessions:  %d\n\n", dwSessCount);


		unique_access_token hToken;

		DWORD ConsoleSessId = WTSGetActiveConsoleSessionId();
		_tprintf("    Console Session = ");
		if ( 0xFFFFFFFF == ConsoleSessId )
			_tprintf("(transition)\n\n");
		else
			_tprintf("%d\n\n", ConsoleSessId);

		CHeapPtr<TOKEN_MANDATORY_LABEL> blob;
		blob.AllocateBytes(2048);
		for ( DWORD ix = 0; ix < dwSessCount ; ++ix )
		{
			_tprintf("    Session ID: %d\n", pSessInfo[ix].SessionId);
			_tprintf("        Window Station Name  : %s\n", pSessInfo[ix].pWinStationName);
			_tprintf("        State                : ");
			switch( pSessInfo[ix].State )
			{
			case WTSActive:
				_tprintf("Active\n");
				break;
			case WTSConnected:
				_tprintf("Connected\n");
				break;
			case WTSConnectQuery:
				_tprintf("ConnectQuery\n");
				break;
			case WTSShadow:
				_tprintf("Shadow\n");
				break;
			case WTSDisconnected:
				_tprintf("Disconnected\n");
				break;
			case WTSIdle:
				_tprintf("Idle\n");
				break;
			case WTSListen:
				_tprintf("Listen\n");
				break;
			case WTSReset:
				_tprintf("Reset\n");
				break;
			case WTSDown:
				_tprintf("Down\n");
				break;
			case WTSInit:
				_tprintf("Init\n");
				break;
			}
			
			CHeapPtr<TCHAR, CWTSAllocator> pInfo;
			DWORD dwBytesReturned = 0;
			ret = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, pSessInfo[ix].SessionId, WTSUserName, &pInfo, &dwBytesReturned);
			if ( ret )
			{
				_tprintf("        WTS User Name        : %s\n", pInfo.m_pData);
			}
			else
			{
				tstring sysErrMsg = SysErrorMessageWithCode();
				//cout << "WTSQuerySessionInformation failed:  " << sysErrMsg << "\n";
				_tprintf("%s\n", sysErrMsg.c_str() );
			}

			if ( WTSQueryUserToken(pSessInfo[ix].SessionId, hToken.get_address_of()) )
			{
				_tprintf("        Token Logon Session  : ");
				TOKEN_STATISTICS tokStats = {0};
				DWORD dwLen = sizeof(TOKEN_STATISTICS);
				if (GetTokenInformation(hToken.get(), TokenStatistics, (LPVOID)&tokStats, dwLen, &dwLen))
				{
					cout << HEX(tokStats.AuthenticationId.HighPart, false) << ":" << HEX(tokStats.AuthenticationId.LowPart, false) << "\n";
				}
				else
				{
					tstring sysErrMsg = SysErrorMessageWithCode();
					//cout << "GetTokenInformation failed:  " << sysErrMsg << "\n";
					_tprintf("%s\n", sysErrMsg.c_str());
				}

				_tprintf("        Token Integrity Level: ");
				DWORD dwLengthNeeded;
				PTOKEN_MANDATORY_LABEL pTIL = blob; // 2048 should be way more than enough for IL
				if (GetTokenInformation(hToken.get(), TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
				{
					DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));

					switch(dwIntegrityLevel)
					{
					case SECURITY_MANDATORY_UNTRUSTED_RID:
						_tprintf("Untrusted");
						break;
					case SECURITY_MANDATORY_LOW_RID:
						_tprintf("Low");
						break;
					case SECURITY_MANDATORY_MEDIUM_RID:
						_tprintf("Medium");
						break;
					case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
						_tprintf("MediumPlus");
						break;
					case SECURITY_MANDATORY_HIGH_RID:
						_tprintf("High");
						break;
					case SECURITY_MANDATORY_SYSTEM_RID:
						_tprintf("System");
						break;
					case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
						_tprintf("ProtectedProcess");
						break;
					default:
						_tprintf("%d", dwIntegrityLevel);
						if (dwIntegrityLevel < SECURITY_MANDATORY_UNTRUSTED_RID)
							_tprintf(" < Untrusted");
						else if (dwIntegrityLevel < SECURITY_MANDATORY_LOW_RID)
							_tprintf(" < Low");
						else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
							_tprintf(" < Medium");
						else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_PLUS_RID)
							_tprintf(" < MediumPlus");
						else if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
							_tprintf(" < High");
						else if (dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
							_tprintf(" < System");
						else if (dwIntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
							_tprintf(" < ProtectedProcess");
						else
							_tprintf(" > ProtectedProcess");
						break;
					}
					_tprintf("\n");
				}
				else
				{
					tstring sysErrMsg = SysErrorMessageWithCode();
					//cout << "GetTokenInformation failed:  " << sysErrMsg << "\n";
					_tprintf("%s\n", sysErrMsg.c_str());
				}
			}
			else
			{
				DWORD dwLastErr = GetLastError();
				switch(dwLastErr)
				{
				case ERROR_PRIVILEGE_NOT_HELD:
					// No output
					break;
				case ERROR_NO_TOKEN:
					_tprintf("        No Token");
					break;
				default:
					//cout 
					//	<< "   WTSQueryUserToken failed: " << sysErrMsg << "\n";
					break;
				}
			}

			_tprintf("\n");
		}
	}
}



void Usage()
{
	_tprintf("Usage:\n"\
		"TSSessions [-NoSD]\n");
	exit(1);
}

void main(int argc, char** argv)
{
	//TODO:  Output an optional banner with the internal name and version number.

	for (int ix = 1; ix < argc; ++ix)
	{
		if (0 == lstrcmpi(argv[ix], "-NoSD") || 0 == lstrcmpi(argv[ix], "/NoSD"))
			bShowSD = false;
		else
			Usage();
	}

	ShowCurrentWinStaDesktop();

	EnumSessions();

	_tprintf("\nWindow stations in the current session:\n");
	if ( ! EnumWindowStations(EnumWindowStationProc, 0) )
	{
		ShowError("EnumWindowStations");
	}

	_tprintf("\n");

}
