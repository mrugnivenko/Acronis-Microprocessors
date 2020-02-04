#pragma once
#define PDP11_WINDOWS

#ifdef PDP11_WINDOWS
#define WIN32_LEAN_AND_MEAN
//#define _CRTDBG_MAP_ALLOC
#pragma warning(push, 3)
#endif // PDP11_WINDOWS


#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <sys/stat.h>

extern "C"
{
//#include <crtdbg.h>
#include <Windows.h>
#include <commdlg.h>
#include <io.h>
}
#ifdef PDP11_WINDOWS
#pragma warning(pop)
#endif // PDP11_WINDOWS


#ifdef PDP11_LINUX
#include <unistd.h>
#endif // PDP11_LINUX
