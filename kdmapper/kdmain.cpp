#ifndef KDLIBMODE

#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include "kdmain.hpp"
#include "kdmapper.hpp"

HANDLE iqvw64e_device_handle;


LONG WINAPI SimplestCrashHandlerKD(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		Log(L"[!!] Crash" << std::endl);

	if (iqvw64e_device_handle)
		intel_driver::Unload(iqvw64e_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}


bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	UNREFERENCED_PARAMETER(mdlptr);
	Log("[+] Callback example called" << std::endl);

	/*
	This callback occurs before call driver entry and
	can be usefull to pass more customized params in
	the last step of the mapping procedure since you
	know now the mapping address and other things
	*/
	return true;
}

DWORD getParentProcess()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	return ppid;
}

//Help people that don't understand how to open a console
void PauseIfParentIsExplorer() {
	DWORD explorerPid = 0;
	GetWindowThreadProcessId(GetShellWindow(), &explorerPid);
	DWORD parentPid = getParentProcess();
	if (parentPid == explorerPid) {
		Log(L"[+] Pausing to allow for debugging" << std::endl);
		Log(L"[+] Press enter to close" << std::endl);
		std::cin.get();
	}
}

int kdmain() {
	setlocale(LC_ALL, "");
	SetUnhandledExceptionFilter(SimplestCrashHandlerKD);

	std::cout << "Driver name to load: ";

	std::cin.ignore();
	std::wstring driver_path;
	std::getline(std::wcin, driver_path);

	/*if (driver_path.size() >= 4 && driver_path.compare(driver_path.size() - 4, 4, L".sys") == 0) {
		std::wcout << L"The driver path ends with .sys" << std::endl;
	}
	else {
		std::wcout << L"The driver path does not end with .sys" << std::endl;
		return -1;
	}*/

	if (!std::filesystem::exists(driver_path)) {
		Log(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}

	iqvw64e_device_handle = intel_driver::Load();

	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE) {
		PauseIfParentIsExplorer();
		return -1;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
		Log(L"[-] Failed to read image to memory" << std::endl);
		intel_driver::Unload(iqvw64e_device_handle);
		PauseIfParentIsExplorer();
		return -1;
	}

	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocatePool;

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(iqvw64e_device_handle, raw_image.data(), 0, 0, free, true, mode, false, callbackExample, &exitCode)) {
		Log(L"[-] Failed to map " << driver_path << std::endl);
		intel_driver::Unload(iqvw64e_device_handle);
		PauseIfParentIsExplorer();
		return -1;
	}

	if (!intel_driver::Unload(iqvw64e_device_handle)) {
		Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
		PauseIfParentIsExplorer();
	}
	Log(L"[+] success" << std::endl);
}

#endif