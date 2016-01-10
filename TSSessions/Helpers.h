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

	static void Free(_In_ void* p) noexcept
	{
		WTSFreeMemory(p);
	}
};

template<class T>
struct handle_base
{
	using pointer = T;
	inline static pointer invalid() noexcept
	{
		return nullptr;
	}
};

struct hdesk_traits : handle_base<HDESK>
{
	static void close(pointer ptr) noexcept
	{
		CloseDesktop(ptr);
	}
};

struct hwinsta_traits : handle_base<HWINSTA>
{
	static void close(pointer ptr) noexcept
	{
		CloseWindowStation(ptr);
	}
};


using unique_hdesk = KennyKerr::unique_handle<hdesk_traits>;
using unique_hwinsta = KennyKerr::unique_handle<hwinsta_traits>;
using unique_access_token = KennyKerr::unique_handle<KennyKerr::null_handle_traits>;
using unique_htoken = KennyKerr::unique_handle<KennyKerr::null_handle_traits>;

