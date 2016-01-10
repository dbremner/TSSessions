#pragma once
#ifdef UNICODE
using tstring = std::wstring;
#else
using tstring = std::string;
#endif
