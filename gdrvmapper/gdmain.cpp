#include <iostream>
#include <string>
#include <vector>
#include <codecvt>
#include <filesystem>
#include <Windows.h>

#include "gdmain.hpp"
#include "global.h"
#include "dropper.h"

void gdmain()
{
    const wchar_t* DriverPath = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";

    std::cout << "Driver name to load: ";

    std::cin.ignore();
    std::wstring target_driver;
    std::getline(std::wcin, target_driver);
    PWCHAR DriverName = const_cast<PWCHAR>(target_driver.c_str());

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (DropDriverFromBytes(DriverPath))
    {
        // Load driver
        Status = WindLoadDriver((PWCHAR)DriverPath, DriverName, FALSE);

        if (NT_SUCCESS(Status))
            printf("Driver loaded successfully\n");

        else
            printf("Error: %08X\n", Status);

        DeleteFile((PWSTR)DriverPath);
    }
}