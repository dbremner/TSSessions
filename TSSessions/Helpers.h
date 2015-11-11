#include "stdafx.h"
#pragma once

//This rather shady class exists so that I can use CHeapPtr with the Remote Desktop API
//I would prefer to use unique_ptr but it doesn't have an overloaded &.
class CWTSAllocator
{
public:
	_Ret_maybenull_ static void* Reallocate(
		_In_ void* /*p*/,
		_In_ size_t /*nBytes*/) throw()
	{
		ATLASSERT(FALSE);
		return nullptr;
	}

	_Ret_maybenull_ static void* Allocate(_In_ size_t /*nBytes*/) throw()
	{
		ATLASSERT(FALSE);
		return nullptr;
	}

	static void Free(_In_ void* p) throw()
	{
		WTSFreeMemory(p);
	}
};

using CLocalHeapPtr = CHeapPtr<char, CLocalAllocator>;
using CWTSHeapPtr = CHeapPtr<char, CWTSAllocator>;

struct hdesk_traits
{
	using pointer = HDESK;

	static pointer invalid()
	{
		return nullptr;
	}

	static void close(pointer ptr)
	{
		CloseDesktop(ptr);
	}

};

struct hwinsta_traits
{
	using pointer = HWINSTA;

	static pointer invalid()
	{
		return nullptr;
	}

	static void close(pointer ptr)
	{
		CloseWindowStation(ptr);
	}

};

using unique_hdesk = KennyKerr::unique_handle<hdesk_traits>;
using unique_hwinsta = KennyKerr::unique_handle<hwinsta_traits>;