#include "common_header.h"
#include "shellcode.hpp"
#include "structs.hpp"

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo);
void SetShellcodeFunctionTable(int index, uint64_t fn);
bool CopyShellcode(uint64_t module, OUT uint64_t* targetLocation);
bool FindDriverObject(const wchar_t* driverName, OUT uint64_t* driverObject);
bool GetDriverDispatch(uint64_t DriverObject, OUT uint64_t* DriverDispatch);
bool HookDriverDispatch(uint64_t DriverObject, uint64_t target);
int LpRun();