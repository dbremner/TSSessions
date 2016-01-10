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
		cout << sObjName << "\n";
	}
}

void ShowObjectFlags(HANDLE hObj)
{
	cout << "Flags:  ";
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

bool SidToString(const PSID pSid, string & sSid, string & sError)
{
	sSid.clear();
	sError.clear();

	CHeapPtr<char, CLocalAllocator> pStrSid;
	if (ConvertSidToStringSidA(pSid, &pStrSid))
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

bool SecDescriptorToString(const PSECURITY_DESCRIPTOR pSD, string & sSDDL, string & sError)
{
	sSDDL.clear();
	sError.clear();
	
	SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;

	CHeapPtr<char, CLocalAllocator> pszSddl;
	if (ConvertSecurityDescriptorToStringSecurityDescriptorA(pSD, SDDL_REVISION_1, si, &pszSddl, NULL))
	{
		sSDDL = pszSddl;
		return true;
	}
	else
	{
		//sError = "ConvertSecurityDescriptorToStringSecurityDescriptorA error: " + SysErrorMessageWithCode();
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
		cout << "(No user)\n";
	}
	else
	{
		string sSid, sError;
		if (SidToString(PSID(buf), sSid, sError))
			cout << sSid << "\n";
		else
			cout << sError << "\n";
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
			cout << sSDDL << "\n";
		else
			cout << sError << "\n";
	}
	else
	{
		ShowError(); //"GetUserObjectSecurity");
	}
	cout << "\n";
}


BOOL  __stdcall EnumDesktopProc(
   LPSTR lpszDesktop,
   LPARAM lParam
)
{
	UNREFERENCED_PARAMETER(lParam);
	cout 
		<< "       Desktop:  " << lpszDesktop << "\n";
	unique_hdesk hDesk{ OpenDesktop(lpszDesktop, 0, FALSE, MAXIMUM_ALLOWED) };//GENERIC_READ);
	if ( !hDesk )
	{
		ShowError("\tOpenDesktop");
	}
	else
	{
		cout << "           SID:  ";
		ShowObjectSid(hDesk.get());
		if (bShowSD)
		{
			cout << "            SD:  ";
			ShowObjectSecurity(hDesk.get());
		}
	}
	cout << "\n";
	return TRUE;
}


BOOL  __stdcall EnumWindowStationProc(
   LPSTR lpszWindowStation,
   LPARAM lParam
)
{
	UNREFERENCED_PARAMETER(lParam);
	cout << "\n    WinSta:  " << lpszWindowStation << "\n";
	unique_hwinsta hWS{ OpenWindowStation(lpszWindowStation, FALSE, MAXIMUM_ALLOWED) };
	if ( !hWS )
	{
		ShowError(); //"\tOpenWindowStation");
	}
	else
	{
		cout << "            ";
		ShowObjectFlags(hWS.get());
		cout << "              SID:  ";
		ShowObjectSid(hWS.get());
		if (bShowSD)
		{
			cout << "               SD:  ";
			ShowObjectSecurity(hWS.get());
		}
		cout << "\n";
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
	cout << "This process/thread running in:\n"\
		"    Session  ";
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

	cout << "    WinSta   " ;
	unique_hwinsta hWS{ GetProcessWindowStation() };
	if ( hWS )
	{
		ShowObjectName(hWS.get());
	}
	else
	{
		ShowError(); //"GetProcessWindowStation");
	}

	cout << "    Desktop  ";
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

	cout << "\nCurrent user input Desktop:  ";
	unique_hdesk hDesk1{ OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED) };
	if ( hDesk1 )
	{
		ShowObjectName(hDesk1.get());
	}
	else
	{
		ShowError(); //"OpenInputDesktop");
	}

	cout << "\n";
}


void EnumSessions()
{
	CHeapPtr<WTS_SESSION_INFOA, CWTSAllocator> pSessInfo;
	DWORD dwSessCount = 0;
	BOOL ret = WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessInfo, &dwSessCount);
	if ( ! ret )
	{
		string sysErrMsg = SysErrorMessageWithCode();
		//cout << "WTSEnumerateSessionsA failed:  " << sysErrMsg << "\n";
		cout << sysErrMsg << "\n";
	}
	else
	{
		cout << "Terminal Sessions:  " << dwSessCount << "\n\n";


		unique_access_token hToken;

		DWORD ConsoleSessId = WTSGetActiveConsoleSessionId();
		cout << "    Console Session = ";
		if ( 0xFFFFFFFF == ConsoleSessId )
			cout << "(transition)" << "\n\n";
		else
			cout << ConsoleSessId << "\n\n";

		for ( DWORD ix = 0; ix < dwSessCount ; ++ix )
		{
			cout 
				<< "    Session ID: " << pSessInfo[ix].SessionId << "\n"
				<< "        Window Station Name  : " << pSessInfo[ix].pWinStationName << "\n";
			cout << "        State                : ";
			switch( pSessInfo[ix].State )
			{
			case WTSActive:
				cout << "Active\n";
				break;
			case WTSConnected:
				cout << "Connected\n";
				break;
			case WTSConnectQuery:
				cout << "ConnectQuery\n";
				break;
			case WTSShadow:
				cout << "Shadow\n";
				break;
			case WTSDisconnected:
				cout << "Disconnected\n";
				break;
			case WTSIdle:
				cout << "Idle\n";
				break;
			case WTSListen:
				cout << "Listen\n";
				break;
			case WTSReset:
				cout << "Reset\n";
				break;
			case WTSDown:
				cout << "Down\n";
				break;
			case WTSInit:
				cout << "Init\n";
				break;
			}
			
			CHeapPtr<char, CWTSAllocator> pInfo;
			DWORD dwBytesReturned = 0;
			ret = WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, pSessInfo[ix].SessionId, WTSUserName, &pInfo, &dwBytesReturned);
			if ( ret )
			{
				cout 
					<< "        WTS User Name        : " << pInfo << "\n";
			}
			else
			{
				string sysErrMsg = SysErrorMessageWithCode();
				//cout << "WTSQuerySessionInformationA failed:  " << sysErrMsg << "\n";
				cout << sysErrMsg << "\n";
			}

			if ( WTSQueryUserToken(pSessInfo[ix].SessionId, hToken.get_address_of()) )
			{
				cout
					<< "        Token Logon Session  : ";
				TOKEN_STATISTICS tokStats = {0};
				DWORD dwLen = sizeof(TOKEN_STATISTICS);
				if (GetTokenInformation(hToken.get(), TokenStatistics, (LPVOID)&tokStats, dwLen, &dwLen))
				{
					cout << HEX(tokStats.AuthenticationId.HighPart, 8, false, false) << ":" << HEX(tokStats.AuthenticationId.LowPart, 8, false, false) << "\n";
				}
				else
				{
					string sysErrMsg = SysErrorMessageWithCode();
					//cout << "GetTokenInformation failed:  " << sysErrMsg << "\n";
					cout << sysErrMsg << "\n";
				}

				cout << "        Token Integrity Level: ";
				DWORD dwLengthNeeded;
				PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)alloca(2048); // 2048 should be way more than enough for IL
				if (GetTokenInformation(hToken.get(), TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
				{
					DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));

					switch(dwIntegrityLevel)
					{
					case SECURITY_MANDATORY_UNTRUSTED_RID:
						cout << "Untrusted";
						break;
					case SECURITY_MANDATORY_LOW_RID:
						cout << "Low";
						break;
					case SECURITY_MANDATORY_MEDIUM_RID:
						cout << "Medium";
						break;
					case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
						cout << "MediumPlus";
						break;
					case SECURITY_MANDATORY_HIGH_RID:
						cout << "High";
						break;
					case SECURITY_MANDATORY_SYSTEM_RID:
						cout << "System";
						break;
					case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
						cout << "ProtectedProcess";
						break;
					default:
						cout << dwIntegrityLevel;
						if (dwIntegrityLevel < SECURITY_MANDATORY_UNTRUSTED_RID)
							cout << " < Untrusted";
						else if (dwIntegrityLevel < SECURITY_MANDATORY_LOW_RID)
							cout << " < Low";
						else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
							cout << " < Medium";
						else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_PLUS_RID)
							cout << " < MediumPlus";
						else if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
							cout << " < High";
						else if (dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
							cout << " < System";
						else if (dwIntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
							cout << " < ProtectedProcess";
						else
							cout << " > ProtectedProcess";	
						break;
					}
					cout << "\n";
				}
				else
				{
					string sysErrMsg = SysErrorMessageWithCode();
					//cout << "GetTokenInformation failed:  " << sysErrMsg << "\n";
					cout << sysErrMsg << "\n";
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
				cout << "        No Token";
					break;
				default:
					//cout 
					//	<< "   WTSQueryUserToken failed: " << sysErrMsg << "\n";
					break;
				}
			}

			cout << "\n";
		}
	}
}



void Usage()
{
	cout
		<< "Usage:\n"\
		"TSSessions [-NoSD]\n";
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

	cout << "\nWindow stations in the current session:\n";
	if ( ! EnumWindowStations(EnumWindowStationProc, 0) )
	{
		ShowError("EnumWindowStations");
	}

	cout << "\n";

}
