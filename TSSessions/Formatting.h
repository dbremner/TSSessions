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
	HEX(unsigned long num, bool bLeading0x)
		: m_num(num), m_bLeading0x(bLeading0x)
	{}

	unsigned long m_num;
	std::streamsize m_width = 8;
	bool m_bLeading0x;
};

inline ostream& operator << ( ostream& os, const HEX & h )
{
	int fmt = os.flags();
	char fillchar = os.fill('0');
	if (h.m_bLeading0x)
		os << "0x" << hex << nouppercase << setw(h.m_width) << h.m_num;
	else
		os << "" << hex << nouppercase << setw(h.m_width) << h.m_num;
	os.fill(fillchar);
	os.flags(fmt);
	return os;
}

inline wostream& operator << ( wostream& os, const HEX & h )
{
	int fmt = os.flags();
	wchar_t fillchar = os.fill(L'0');
	if (h.m_bLeading0x) 
		os << L"0x" << hex << nouppercase << setw(h.m_width) << h.m_num ;
	else 
		os << L"" << hex << nouppercase << setw(h.m_width) << h.m_num ;
	os.fill(fillchar);
	os.flags(fmt);
	return os;
}



inline tstring SysErrorMessageWithCode()
{
	DWORD dwErrCode = GetLastError();
	CHeapPtr<TCHAR, CLocalAllocator> pszErrMsg;
	std::stringstream sRetval;
	DWORD flags =
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_SYSTEM ;

	if ( FormatMessage(
		flags,
		NULL, 
		dwErrCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPSTR)&pszErrMsg,
		0,
		NULL ) )
	{
		tstring sErrMsg = pszErrMsg;
		size_t ixLast = sErrMsg.find_last_not_of("\r\n");
		if ( tstring::npos != ixLast )
			sErrMsg = sErrMsg.substr(0, ixLast + 1);
		sRetval << sErrMsg << " (Error # " << dwErrCode << " = " << HEX(dwErrCode, true) << ")";
	}
	else
	{
		sRetval << "Error # " << dwErrCode << " (" << HEX(dwErrCode, true) << ")";
	}
	return sRetval.str();
}

inline void ShowError(LPCTSTR sContext = nullptr)
{
	tstring sysErrMsg = SysErrorMessageWithCode();
	if (sContext && *sContext)
		_tprintf("%s error, %s\n", sContext, sysErrMsg.c_str() );
	else
		_tprintf("%s\n", sysErrMsg.c_str() );
}
