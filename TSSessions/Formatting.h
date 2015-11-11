// Formatting.h
// Written by Aaron Margosis, Microsoft Services
#pragma once
/*
THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (C) 2007-2012.  Microsoft Corporation.  All rights reserved.
*/

// Structure and operator to insert a zero-filled hex-formatted number into a stream.
struct HEX
{
	HEX(unsigned long num, unsigned long fieldwidth = 8, bool bUpcase = false, bool bLeading0x = true)
		: m_num(num), m_width(fieldwidth), m_upcase(bUpcase), m_bLeading0x(bLeading0x)
		{}

	unsigned long m_num;
	unsigned long m_width;
	bool m_upcase;
	bool m_bLeading0x;
};

inline ostream& operator << ( ostream& os, const HEX & h )
{
	int fmt = os.flags();
	char fillchar = os.fill('0');
	os << (h.m_bLeading0x ? "0x" : "") << hex << (h.m_upcase ? uppercase : nouppercase) << setw(h.m_width) << h.m_num ;
	os.fill(fillchar);
	os.flags(fmt);
	return os;
}

inline wostream& operator << ( wostream& os, const HEX & h )
{
	int fmt = os.flags();
	wchar_t fillchar = os.fill(L'0');
	os << (h.m_bLeading0x ? L"0x" : L"") << hex << (h.m_upcase ? uppercase : nouppercase) << setw(h.m_width) << h.m_num ;
	os.fill(fillchar);
	os.flags(fmt);
	return os;
}



inline std::string SysErrorMessageWithCode()
{
	DWORD dwErrCode = GetLastError();
	LPSTR pszErrMsg = NULL;
	std::stringstream sRetval;
	DWORD flags =
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_SYSTEM ;

	if ( FormatMessageA(
		flags,
		NULL, 
		dwErrCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPSTR)&pszErrMsg,
		0,
		NULL ) )
	{
		string sErrMsg = pszErrMsg;
		size_t ixLast = sErrMsg.find_last_not_of("\r\n");
		if ( string::npos != ixLast )
			sErrMsg = sErrMsg.substr(0, ixLast + 1);
		sRetval << sErrMsg << " (Error # " << dwErrCode << " = " << HEX(dwErrCode) << ")";
		LocalFree(pszErrMsg);
	}
	else
	{
		sRetval << "Error # " << dwErrCode << " (" << HEX(dwErrCode) << ")";
	}
	return sRetval.str();
}

inline void ShowError(LPCSTR sContext = NULL)
{
	string sysErrMsg = SysErrorMessageWithCode();
	if (sContext && *sContext)
		cout << sContext << " error, " << sysErrMsg << endl;
	else
		cout << sysErrMsg << endl;
}
