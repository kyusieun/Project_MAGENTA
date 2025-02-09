/*
	WARNING: utils.hpp must be the first file included...
	this is because i use getenv and that requires _CRT_SECURE_NO_WARNINGS...
*/

#pragma once
#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "ntdll.lib")

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>

#include <functional>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "ia32.hpp"

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
     HANDLE Section;
     PVOID MappedBase;
     PVOID ImageBase;
     ULONG ImageSize;
     ULONG Flags;
     USHORT LoadOrderIndex;
     USHORT InitOrderIndex;
     USHORT LoadCount;
     USHORT OffsetToFileName;
     UCHAR FullPathName[256];
 } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#define SystemKernelVaShadowInformation     (SYSTEM_INFORMATION_CLASS) 196
typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION
{
	struct
	{
		ULONG KvaShadowEnabled : 1;
		ULONG KvaShadowUserGlobal : 1;
		ULONG KvaShadowPcid : 1;
		ULONG KvaShadowInvpcid : 1;
		ULONG KvaShadowRequired : 1;
		ULONG KvaShadowRequiredAvailable : 1;
		ULONG InvalidPteBit : 6;
		ULONG L1DataCacheFlushSupported : 1;
		ULONG L1TerminalFaultMitigationPresent : 1;
		ULONG Reserved : 18;
	} KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, * PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

namespace utils
{
	inline std::uintptr_t scan(std::uintptr_t base, std::uint32_t size, const char* pattern, const char* mask)
	{
		static const auto check_mask =
			[&](const char* base, const char* pattern, const char* mask) -> bool
		{
			for (; *mask; ++base, ++pattern, ++mask)
				if (*mask == 'x' && *base != *pattern)
					return false;
			return true;
		};

		size -= strlen(mask);
		for (auto i = 0; i <= size; ++i)
		{
			void* addr = (void*)&(((char*)base)[i]);
			if (check_mask((char*)addr, pattern, mask))
				return reinterpret_cast<std::uintptr_t>(addr);
		}

		return NULL;
	}

	inline std::uint32_t get_pid(const wchar_t* proc_name)
	{
		PROCESSENTRY32 proc_info;
		proc_info.dwSize = sizeof(proc_info);

		HANDLE proc_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (proc_snapshot == INVALID_HANDLE_VALUE)
			return NULL;

		Process32First(proc_snapshot, &proc_info);
		if (!wcscmp(proc_info.szExeFile, proc_name))
		{
			CloseHandle(proc_snapshot);
			return proc_info.th32ProcessID;
		}

		while (Process32Next(proc_snapshot, &proc_info))
		{
			if (!wcscmp(proc_info.szExeFile, proc_name))
			{
				CloseHandle(proc_snapshot);
				return proc_info.th32ProcessID;
			}
		}

		CloseHandle(proc_snapshot);
		return NULL;
	}


	namespace kmodule
	{
		using kmodule_callback_t = std::function<bool(PRTL_PROCESS_MODULE_INFORMATION, const char*)>;
		inline void each_module(kmodule_callback_t callback)
		{
			void* buffer = nullptr;
			DWORD buffer_size = NULL;

			auto status = NtQuerySystemInformation(
				static_cast<SYSTEM_INFORMATION_CLASS>(0xB),
				buffer, buffer_size, &buffer_size);

			while (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				VirtualFree(buffer, NULL, MEM_RELEASE);
				buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				status = NtQuerySystemInformation(
					static_cast<SYSTEM_INFORMATION_CLASS>(0xB),
					buffer, buffer_size, &buffer_size);
			}

			if (!NT_SUCCESS(status))
			{
				VirtualFree(buffer, NULL, MEM_RELEASE);
				return;
			}

			const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
			for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
			{
				auto full_path = std::string(
					reinterpret_cast<char*>(
						modules->Modules[idx].FullPathName));

				if (full_path.find("\\SystemRoot\\") != std::string::npos)
					full_path.replace(full_path.find("\\SystemRoot\\"),
						sizeof("\\SystemRoot\\") - 1, std::string(getenv("SYSTEMROOT")).append("\\"));

				else if (full_path.find("\\??\\") != std::string::npos)
					full_path.replace(full_path.find("\\??\\"), 
						sizeof("\\??\\") - 1, "");

				if (!callback(&modules->Modules[idx], full_path.c_str()))
				{
					VirtualFree(buffer, NULL, MEM_RELEASE);
					return;
				}
			}

			VirtualFree(buffer, NULL, MEM_RELEASE);
			return;
		}

		inline std::uintptr_t get_base(const char* module_name)
		{
			void* buffer = nullptr;
			DWORD buffer_size = NULL;

			auto status = NtQuerySystemInformation(
				static_cast<SYSTEM_INFORMATION_CLASS>(0xB),
				buffer, buffer_size, &buffer_size);

			while (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				VirtualFree(buffer, NULL, MEM_RELEASE);
				buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				status = NtQuerySystemInformation(
					static_cast<SYSTEM_INFORMATION_CLASS>(0xB),
					buffer, buffer_size, &buffer_size);
			}

			if (!NT_SUCCESS(status))
			{
				VirtualFree(buffer, NULL, MEM_RELEASE);
				return NULL;
			}

			const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
			for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
			{
				const auto current_module_name =
					std::string(reinterpret_cast<char*>(
						modules->Modules[idx].FullPathName) +
						modules->Modules[idx].OffsetToFileName);

				if (!_stricmp(current_module_name.c_str(), module_name))
				{
					const auto result =
						reinterpret_cast<std::uint64_t>(
							modules->Modules[idx].ImageBase);

					VirtualFree(buffer, NULL, MEM_RELEASE);
					return result;
				}
			}

			VirtualFree(buffer, NULL, MEM_RELEASE);
			return NULL;
		}

		inline std::uintptr_t get_export(const char* module_name, const char* export_name)
		{
			void* buffer = nullptr;
			DWORD buffer_size = NULL;

			NTSTATUS status = NtQuerySystemInformation(
				static_cast<SYSTEM_INFORMATION_CLASS>(0xB),
				buffer,
				buffer_size,
				&buffer_size
			);

			while (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				VirtualFree(buffer, 0, MEM_RELEASE);
				buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				status = NtQuerySystemInformation(
					static_cast<SYSTEM_INFORMATION_CLASS>(0xB),
					buffer,
					buffer_size,
					&buffer_size
				);
			}

			if (!NT_SUCCESS(status))
			{
				VirtualFree(buffer, 0, MEM_RELEASE);
				return NULL;
			}

			const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
			for (auto idx = 0u; idx < modules->NumberOfModules; ++idx)
			{
				// find module and then load library it
				const std::string current_module_name =
					std::string(reinterpret_cast<char*>(
						modules->Modules[idx].FullPathName) +
						modules->Modules[idx].OffsetToFileName
					);

				if (!_stricmp(current_module_name.c_str(), module_name))
				{
					auto full_path = std::string(
						reinterpret_cast<char*>(
							modules->Modules[idx].FullPathName));

					full_path.replace(full_path.find("\\SystemRoot\\"),
						sizeof("\\SystemRoot\\") - 1, std::string(getenv("SYSTEMROOT")).append("\\"));

					const auto module_base =
						LoadLibraryExA(
							full_path.c_str(),
							NULL,
							DONT_RESOLVE_DLL_REFERENCES
						);

					const auto image_base =
						reinterpret_cast<std::uintptr_t>(
							modules->Modules[idx].ImageBase);

					// free the RTL_PROCESS_MODULES buffer...
					VirtualFree(buffer, NULL, MEM_RELEASE);

					const auto rva =
						reinterpret_cast<std::uintptr_t>(
							GetProcAddress(module_base, export_name)) -
						reinterpret_cast<std::uintptr_t>(module_base);

					return image_base + rva;
				}
			}

			VirtualFree(buffer, NULL, MEM_RELEASE);
			return NULL;
		}
	}

	namespace pe
	{
		using section_callback_t = std::function<bool(PIMAGE_SECTION_HEADER, std::uintptr_t)>;

		// returns an std::vector containing all of the bytes of the section
		// and also the RVA from the image base to the beginning of the section...
		inline std::pair<std::vector<std::uint8_t>, std::uint32_t> get_section(std::uintptr_t module_base, const char* section_name)
		{
			const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<PIMAGE_DOS_HEADER>(module_base)->e_lfanew + module_base);

			const auto section_header =
				reinterpret_cast<PIMAGE_SECTION_HEADER>(
					reinterpret_cast<std::uintptr_t>(nt_headers) + sizeof(DWORD)
						+ sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader);

			for (auto idx = 0u; idx < nt_headers->FileHeader.NumberOfSections; ++idx)
			{
				const auto _section_name = 
					reinterpret_cast<char*>(
						section_header[idx].Name);

				// sometimes section names are not null terminated...
				if (!strncmp(_section_name, section_name, strlen(section_name) - 1))
				{
					const auto section_base = 
						reinterpret_cast<std::uint8_t*>(
							module_base + section_header[idx].VirtualAddress);

					const auto section_end = 
						reinterpret_cast<std::uint8_t*>(
							section_base + section_header[idx].Misc.VirtualSize);

					std::vector<std::uint8_t> section_bin(section_base, section_end);
					return { section_bin, section_header[idx].VirtualAddress };
				}
			}

			return { {}, {} };
		}

		inline void each_section(section_callback_t callback, std::uintptr_t module_base)
		{
			if (!module_base)
				return;

			const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<PIMAGE_DOS_HEADER>(module_base)->e_lfanew + module_base);

			const auto section_header =
				reinterpret_cast<PIMAGE_SECTION_HEADER>(
					reinterpret_cast<std::uintptr_t>(nt_headers) + sizeof(DWORD) 
						+ sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader);

			for (auto idx = 0u; idx < nt_headers->FileHeader.NumberOfSections; ++idx)
			{
				const auto _section_name =
					reinterpret_cast<char*>(
						section_header[idx].Name);

				// keep looping until the callback returns false...
				if (!callback(&section_header[idx], module_base))
					return;
			}
		}
	}

	namespace rop
	{
		// https://j00ru.vexillium.org/2011/06/smep-what-is-it-and-how-to-beat-it-on-windows/
		// http://blog.ptsecurity.com/2012/09/bypassing-intel-smep-on-windows-8-x64.html?m=1
		// just implimented the rop information from these posts...
		inline std::uintptr_t find_kgadget(const char* sig, const char* mask)
		{
			std::uintptr_t result = 0u;
			kmodule::each_module(
				[&](auto kernel_image, const char* image_name) -> bool
				{
					utils::pe::each_section(
						[&](auto section_header, std::uintptr_t image_base) -> bool
						{
							if (section_header->Characteristics & IMAGE_SCN_CNT_CODE &&
								!(section_header->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
							{
								const auto rop_gadget =
									utils::scan(image_base + section_header->VirtualAddress,
										section_header->Misc.VirtualSize, sig, mask);

								if(rop_gadget)
									result = (rop_gadget - image_base) + 
										reinterpret_cast<std::uintptr_t>(kernel_image->ImageBase);

								return !rop_gadget;
							}
							return true;
						},
						reinterpret_cast<std::uintptr_t>(
							LoadLibraryExA(image_name,
								NULL, DONT_RESOLVE_DLL_REFERENCES))
					);
					return !result;
				}
			);
			return result;
		}
	}
}