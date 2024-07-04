# Project MAGENTA


Project MAGENTA is an integrated penetration testing tool that diagnoses the possibity of BYOVD attacks on your system.
# Prerequisites
x64 windows 10

# How it work
This tool is used to test and analyze various driver vulnerabilities.
Below are the four features this tool includes:

- DSEFix
    - It uses WinNT/Turla VirtualBox kernel mode exploit technique to overwrite global system variable controlling DSE behavior, which itself located in kernel memory space.
- Fixed Image
    - Fixed Image is a simple tool that exploits iqvw64e.sys Intel driver to manually map non-signed drivers in memory
- MSREXEC
    - msrexec is a tool that can be used to elevate arbitrary MSR writes to kernel execution on 64 bit Windows-10 systems. This tool is part of the VDM (vulnerable driver manipulation) namespace and can be integrated into any prior VDM tool. Although this tool falls under the VDM namespace, Voyager and bluepill can be used to provide arbitrary wrmsr writes.
- LPMAPPER
    - Allocate memory to make the `data section` of Windows' own drivers, such as `beep.sys`, executable without having to raise the driver, allowing code to be allocated and executed

![Entry](./image/Entry.png)
# References
https://github.com/hfiref0x/DSEFix?tab=readme-ov-file

https://github.com/TheCruZ/kdmapper

https://github.com/backengineering/msrexec

https://github.com/VollRagm/lpmapper



[BLOG](https://glowing-jewel-096.notion.site/Driver-Manual-Mapping-f0f51d7a8c7f4c5a9cbde6de1e2ac1d0)


