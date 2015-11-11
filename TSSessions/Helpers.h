#pragma once

//This rather shady class exists so that I can use CHeapPtr with the Remote Desktop API
//I would prefer to use unique_ptr but it doesn't have an overloaded &.
class CWTSAllocator
{
public:
	_Ret_maybenull_ _Post_writable_byte_size_(nBytes) static void* Reallocate(
		_In_ void* p,
		_In_ size_t nBytes) throw()
	{
		return ATLASSERT(FALSE);
	}

	_Ret_maybenull_ _Post_writable_byte_size_(nBytes) static void* Allocate(_In_ size_t nBytes) throw()
	{
		return ATLASSERT(FALSE);
	}

	static void Free(_In_ void* p) throw()
	{
		WTSFreeMemory(p);
	}
};