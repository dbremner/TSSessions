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
		cout << sObjName << endl;
	}
}

void ShowObjectFlags(HANDLE hObj)
{
	cout << "Flags:  ";
	USEROBJECTFLAGS uoFlags;
	SecureZeroMemory(&uoFlags, sizeof(uoFlags));
	DWORD nLenNeeded = 0;
	if ( !GetUserObjectInformation(hObj, UOI_FLAGS, &uoFlags, sizeof(uoFlags), &nLenNeeded) )
	{
		ShowError(); //"GetUserObjectInformation (UOI_FLAGS)");
	}
	else
	{
		cout << HEX(uoFlags.dwFlags) << endl;
	}
}

bool SidToString(const PSID pSid, string & sSid, string & sError)
{
	sSid.clear();
	sError.clear();

	LPSTR pStrSid = NULL;
	if (ConvertSidToStringSidA(pSid, &pStrSid))
	{
		sSid = pStrSid;
		LocalFree(pStrSid);
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

	LPSTR pszSddl = NULL;
	if (ConvertSecurityDescriptorToStringSecurityDescriptorA(pSD, SDDL_REVISION_1, si, &pszSddl, NULL))
	{
		sSDDL = pszSddl;
		LocalFree(pszSddl);
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
		cout << "(No user)" << endl;
	}
	else
	{
		string sSid, sError;
		if (SidToString(PSID(buf), sSid, sError))
			cout << sSid << endl;
		else
			cout << sError << endl;
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
			cout << sSDDL << endl;
		else
			cout << sError << endl;
	}
	else
	{
		ShowError(); //"GetUserObjectSecurity");
	}
	cout << endl;
}


BOOL  __stdcall EnumDesktopProc(
   LPSTR lpszDesktop,
   DWORD lParam
)
{
	UNREFERENCED_PARAMETER(lParam);
	cout 
		<< "       Desktop:  " << lpszDesktop << endl;
	HDESK hDesk = OpenDesktop(lpszDesktop, 0, FALSE, MAXIMUM_ALLOWED);//GENERIC_READ);
	if ( NULL == hDesk )
	{
		ShowError("\tOpenDesktop");
	}
	else
	{
		cout << "           SID:  ";
		ShowObjectSid(hDesk);
		if (bShowSD)
		{
			cout << "            SD:  ";
			ShowObjectSecurity(hDesk);
		}
		CloseDesktop(hDesk);
	}
	cout << endl;
	return TRUE;
}


BOOL  __stdcall EnumWindowStationProc(
   LPSTR lpszWindowStation,
   DWORD lParam
)
{
	UNREFERENCED_PARAMETER(lParam);
	cout << endl <<
		"    WinSta:  " << lpszWindowStation << endl;
	HWINSTA hWS = OpenWindowStation(lpszWindowStation, FALSE, MAXIMUM_ALLOWED);
	if ( NULL == hWS )
	{
		ShowError(); //"\tOpenWindowStation");
	}
	else
	{
		cout << "            ";
		ShowObjectFlags(hWS);
		cout << "              SID:  ";
		ShowObjectSid(hWS);
		if (bShowSD)
		{
			cout << "               SD:  ";
			ShowObjectSecurity(hWS);
		}
		cout << endl;
		HWINSTA hWS_save = GetProcessWindowStation();
		if ( SetProcessWindowStation(hWS) )
		{
			BOOL bEDret = EnumDesktops(hWS, (DESKTOPENUMPROCA)EnumDesktopProc, 0);
			if ( ! bEDret )
			{
				ShowError("\tEnumDesktops");
			}
			SetProcessWindowStation(hWS_save);
		}
		else
			ShowError("\tSetProcessWindowStation");
		CloseWindowStation(hWS);
	}

	return TRUE;
}


void ShowCurrentWinStaDesktop()
{
	cout << "This process/thread running in:" << endl;

	cout << "    Session  ";
	HANDLE hToken = NULL;
	if ( ! OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) )
	{
		ShowError(); //"OpenProcessToken");
	}
	else
	{
		DWORD dwSessionID = 0, dwRetLen = 0;
		if ( ! GetTokenInformation(hToken, TokenSessionId, &dwSessionID, sizeof(dwSessionID), &dwRetLen) )
		{
			ShowError(); //"GetTokenInformation");
		}
		else
		{
			cout << dwSessionID << endl;
		}
		CloseHandle(hToken);
	}

	cout << "    WinSta   " ;
	HWINSTA hWS = GetProcessWindowStation();
	if ( hWS )
	{
		ShowObjectName(hWS);
		CloseWindowStation(hWS);
	}
	else
	{
		ShowError(); //"GetProcessWindowStation");
	}

	cout << "    Desktop  ";
	HDESK hDesk0 = GetThreadDesktop(GetCurrentThreadId());
	if ( hDesk0 )
	{
		ShowObjectName(hDesk0);
		CloseDesktop(hDesk0);
	}
	else
	{
		ShowError(); //"GetThreadDesktop");
	}

	cout << endl
		<< "Current user input Desktop:  ";
	HDESK hDesk1 = OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED);
	if ( hDesk1 )
	{
		ShowObjectName(hDesk1);
		CloseDesktop(hDesk1);
	}
	else
	{
		ShowError(); //"OpenInputDesktop");
	}

	cout << endl;
}


void EnumSessions()
{
	PWTS_SESSION_INFOA pSessInfo = NULL;
	DWORD dwSessCount = 0;
	BOOL ret = WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessInfo, &dwSessCount);
	if ( ! ret )
	{
		string sysErrMsg = SysErrorMessageWithCode();
		//cout << "WTSEnumerateSessionsA failed:  " << sysErrMsg << endl;
		cout << sysErrMsg << endl;
	}
	else
	{
		cout 
			<< "Terminal Sessions:  " << dwSessCount << endl
			<< endl;


		HANDLE hToken = NULL;

		DWORD ConsoleSessId = WTSGetActiveConsoleSessionId();
		cout << "    Console Session = ";
		if ( 0xFFFFFFFF == ConsoleSessId )
			cout << "(transition)" << endl << endl;
		else
			cout << ConsoleSessId << endl << endl;


		for ( DWORD ix = 0; ix < dwSessCount ; ++ix )
		{
			cout 
				<< "    Session ID: " << pSessInfo[ix].SessionId << endl
				<< "        Window Station Name  : " << pSessInfo[ix].pWinStationName << endl;
			cout
				<< "        State                : ";
			switch( pSessInfo[ix].State )
			{
			case WTSActive:
				cout << "Active" << endl;
				break;
			case WTSConnected:
				cout << "Connected" << endl;
				break;
			case WTSConnectQuery:
				cout << "ConnectQuery" << endl;
				break;
			case WTSShadow:
				cout << "Shadow" << endl;
				break;
			case WTSDisconnected:
				cout << "Disconnected" << endl;
				break;
			case WTSIdle:
				cout << "Idle" << endl;
				break;
			case WTSListen:
				cout << "Listen" << endl;
				break;
			case WTSReset:
				cout << "Reset" << endl;
				break;
			case WTSDown:
				cout << "Down" << endl;
				break;
			case WTSInit:
				cout << "Init" << endl;
				break;
			}
			
			LPSTR pInfo = NULL;
			DWORD dwBytesReturned = 0;
			ret = WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, pSessInfo[ix].SessionId, WTSUserName, &pInfo, &dwBytesReturned);
			if ( ret )
			{
				cout 
					<< "        WTS User Name        : " << pInfo << endl;
				WTSFreeMemory(pInfo);
				pInfo = NULL;
			}
			else
			{
				string sysErrMsg = SysErrorMessageWithCode();
				//cout << "WTSQuerySessionInformationA failed:  " << sysErrMsg << endl;
				cout << sysErrMsg << endl;
			}

			if ( WTSQueryUserToken(pSessInfo[ix].SessionId, &hToken) )
			{
				cout
					<< "        Token Logon Session  : ";
				TOKEN_STATISTICS tokStats = {0};
				DWORD dwLen = sizeof(TOKEN_STATISTICS);
				if (GetTokenInformation(hToken, TokenStatistics, (LPVOID)&tokStats, dwLen, &dwLen))
				{
					cout << HEX(tokStats.AuthenticationId.HighPart, 8, false, false) << ":" << HEX(tokStats.AuthenticationId.LowPart, 8, false, false) << endl;
				}
				else
				{
					string sysErrMsg = SysErrorMessageWithCode();
					//cout << "GetTokenInformation failed:  " << sysErrMsg << endl;
					cout << sysErrMsg << endl;
				}

				cout
					<< "        Token Integrity Level: ";
				DWORD dwLengthNeeded;
				PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)alloca(2048); // 2048 should be way more than enough for IL
				if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
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
					cout << endl;
				}
				else
				{
					string sysErrMsg = SysErrorMessageWithCode();
					//cout << "GetTokenInformation failed:  " << sysErrMsg << endl;
					cout << sysErrMsg << endl;
				}

				CloseHandle(hToken);
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
				cout
					<< "        No Token";
					break;
				default:
					//cout 
					//	<< "   WTSQueryUserToken failed: " << sysErrMsg << endl;
					break;
				}
			}

			cout << endl;
		}
		WTSFreeMemory(pSessInfo);
	}
}



void Usage()
{
	cout
		<< "Usage:" << endl
		<< "TSSessions [-NoSD]" << endl;
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

	cout << endl
		<< "Window stations in the current session:" << endl;
	if ( ! EnumWindowStations((WINSTAENUMPROCA)EnumWindowStationProc, 0) )
	{
		ShowError("EnumWindowStations");
	}

	cout << endl;

}
