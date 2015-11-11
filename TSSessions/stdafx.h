// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
/*
THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (C) 2007-2012.  Microsoft Corporation.  All rights reserved.
*/

#pragma once
#define _WIN32_WINNT 0x0501
#include "targetver.h"
#include <windows.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
using namespace std;
#include <tchar.h>
#include <sddl.h>
#include <atlbase.h>

//DX
#include "handle.h"

#include "Helpers.h"

#include "Formatting.h"

