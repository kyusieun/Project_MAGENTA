#include "../common_header.h"

void DSEFixRun(std::string target_driver);

static
NTSTATUS
RtlOpenFile(
	_Out_ PHANDLE FileHandle,
	_In_ PCWCHAR Filename
);

NTSTATUS
MapFileSectionView(
	_In_ PCWCHAR Filename,
	_In_ BOOLEAN ForceDisableAslr,
	_Out_ PVOID* ImageBase,
	_Out_ PSIZE_T ViewSize
);

PVOID
GetProcedureAddress(
	_In_ ULONG_PTR DllBase,
	_In_ PCSTR RoutineName
);

static
NTSTATUS
FindKernelModule(
	_In_ PCCH ModuleName,
	_Out_ PULONG_PTR ModuleBase
);

static
LONG
QueryCiEnabled(
	_In_ PVOID MappedBase,
	_In_ SIZE_T SizeOfImage,
	_In_ ULONG_PTR KernelBase,
	_Out_ PULONG_PTR gCiEnabledAddress
);

static
LONG
QueryCiOptions(
	_In_ PVOID MappedBase, // ci.dll file
	_In_ ULONG_PTR KernelBase, //ci.dll kernel base
	_Out_ PULONG_PTR gCiOptionsAddress
);

static
NTSTATUS
AnalyzeCi(
	_Out_ PVOID* CiOptionsAddress
);

static int ConvertToNtPath(PWCHAR Dst, PWCHAR Src);

static void FileNameToServiceName(PWCHAR ServiceName, PWCHAR FileName);

static NTSTATUS CreateDriverService(PWCHAR ServiceName, PWCHAR FileName);

static void DeleteService(PWCHAR ServiceName);

static BOOLEAN IsCiEnabled();

static NTSTATUS LoadDriver(PWCHAR ServiceName);

static NTSTATUS UnloadDriver(PWCHAR ServiceName);

static
NTSTATUS
OpenDeviceHandle(
	_Out_ PHANDLE DeviceHandle,
	_In_ BOOLEAN PrintErrors
);

static
NTSTATUS
TriggerExploit(
	_In_ PWSTR LoaderServiceName,
	_In_ PVOID CiVariableAddress,
	_In_ ULONG CiOptionsValue,
	_Out_opt_ PULONG OldCiOptionsValue
);

NTSTATUS
WindLoadDriver(
	_In_ PWCHAR LoaderName,
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
);

NTSTATUS
WindUnloadDriver(
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
);

bool CompareByte(const PUCHAR data, const PUCHAR pattern, UINT32 len);