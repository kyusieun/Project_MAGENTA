import subprocess
import requests
from requests.exceptions import ConnectionError, RequestException
from bs4 import BeautifulSoup
import os
import time
import sys
import re
import json
import pandas as pd
import csv

# 불 전역 변수 설정해서 find_match에서 결과값 설정
match_res = []

#----------------------------------------------------------------------------------------------------------------------------------------------
import pefile
import sys


def is_64bit(pe):
    return pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]


def find_wrmsr_patterns(data, patterns):
    positions = []
    for pattern in patterns:
        start = 0
        while True:
            start = data.find(pattern, start)
            if start == -1:
                break
            positions.append(start)
            start += len(pattern)
    return positions


def check_imports(pe, imports):
    found_imports = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and imp.name.decode() in imports:
                found_imports.append(imp.name.decode())
    return found_imports


def helper(file_path):
    pe = pefile.PE(file_path)

    if is_64bit(pe):
        print("64-bit system detected")
        wrmsr_patterns = [
            b"\x48\x8B\x0D",  # mov rcx, [address]
            b"\x48\x8B\x05",  # mov rax, [address]
            b"\x48\x8B\x15",  # mov rdx, [address]
            b"\x0F\x30",  # wrmsr
        ]
    else:
        print("32-bit system detected")
        wrmsr_patterns = [
            b"\x8B\x0D",  # mov ecx, [address]
            b"\x8B\x05",  # mov eax, [address]
            b"\x8B\x15",  # mov edx, [address]
            b"\x0F\x30",  # wrmsr
        ]

    # Locate .text section (code section)
    for section in pe.sections:
        if b".text" in section.Name:
            code_section_data = section.get_data()
            code_section_start = section.VirtualAddress
            break
    else:
        print("No .text section found")
        return

    name = file_path.split('\\')[-1][:-4]
    # result_path = ".\\Secondary_Examination\\" + name + ".txt"
    result_path = ".\\" + name + ".txt"
    f_result = open(result_path, "w")


    # Search for patterns in the .text section
    f_result.write("=== WRMSR PATTERN CHECK RESULT ===\n\n")
    positions = find_wrmsr_patterns(code_section_data, wrmsr_patterns)
    if positions:
        print("wrmsr pattern found at addresses:")
        f_result.write("wrmsr pattern found at addresses:\n")
        for pos in positions:
            print(f"0x{code_section_start + pos:08X}")
            f_result.write(f"0x{code_section_start + pos:08X}"+"\n")
    else:
        print("wrmsr pattern not found")
        f_result.write("wrmsr pattern not found\n")


    # Check IAT for specific imports
    imports_to_check = [
        "MmMapIoSpace",
        "MmGetPhysicalAddress",
        "MmMapLockedPagesSpecifyCache",
        "MmAllocatePagesForMdl",
        "MmAllocatePagesForMdlEx",
        "ZwOpenSection",
        "ZwMapViewOfSection",
        "IoCreateDevice",
    ]

    f_result.write("\n\n=== VULNERABLE LIBRARIES CHECK RESULT ===\n\n")

    found_imports = check_imports(pe, imports_to_check)

    if "IoCreateDevice" not in found_imports:
        print("IoCreateDevice not found in IAT. Skipping IAT imports check.")
        return

    # result.append("found_imps")

    if found_imports:
        print("Following imports found in IAT:")
        f_result.write("Following imports found in IAT:\n")
        for imp in found_imports:
            print(f"- {imp}")
            f_result.write(f"- {imp}"+"\n")
    else :
        f_result.write("No Vulnerable Library found\n")

    f_result.close()
    

    # Check for both ZwOpenSection and ZwMapViewOfSection
    if "ZwOpenSection" in found_imports and "ZwMapViewOfSection" in found_imports:
        print("Both ZwOpenSection and ZwMapViewOfSection are imported.")

    elif "ZwOpenSection" in found_imports or "ZwMapViewOfSection" in found_imports:
        print("ZwOpenSection or ZwMapViewOfSection is imported, but not both.")
    


#----------------------------------------------------------------------------------------------------------------------------------------------
#vuln driver check

#ref    {GitHub:https://github.com/RogueCyberSecurityChannel}

def welcome():
    print(r'''
_____/\\\\\\\\\\\____/\\\________/\\\_______/\\\\\_______/\\\________/\\\__/\\\\\\\\\\\\____        
 ___/\\\/////////\\\_\///\\\____/\\\/______/\\\///\\\____\/\\\_______\/\\\_\/\\\////////\\\__       
  __\//\\\______\///____\///\\\/\\\/______/\\\/__\///\\\__\//\\\______/\\\__\/\\\______\//\\\_      
   ___\////\\\_____________\///\\\/_______/\\\______\//\\\__\//\\\____/\\\___\/\\\_______\/\\\_     
    ______\////\\\____________\/\\\_______\/\\\_______\/\\\___\//\\\__/\\\____\/\\\_______\/\\\_    
     _________\////\\\_________\/\\\_______\//\\\______/\\\_____\//\\\/\\\_____\/\\\_______\/\\\_   
      __/\\\______\//\\\________\/\\\________\///\\\__/\\\________\//\\\\\______\/\\\_______/\\\__  
       _\///\\\\\\\\\\\/_________\/\\\__________\///\\\\\/__________\//\\\_______\/\\\\\\\\\\\\/___ 
        ___\///////////___________\///_____________\/////_____________\///________\////////////_____
''')
    
    print(r'''
          
This tool is designed to detect vulnerable drivers on a Windows system. It performs the following tasks:
1. Queries and hashes local system drivers.
2. Retrieves and parses updated vulnerable driver lists from the web.
3. Matches local drivers against known vulnerable drivers using both name and hash.
4. Displays the results and saves them to CSV files.
5. Analyzes matched drivers further and saves the analysis to additional text files.
''')

def web_scrape_and_process(url, class_to_scrape):
    extracted_data = []
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        elements_with_class = soup.find_all(class_= class_to_scrape)
        for element in elements_with_class:
            extracted_data.append(element.text)
    return extracted_data

def get_json_endpoint(url):
    result = []
    response = requests.get(url)
    if response.ok is True:
        result = json.loads(response.text)
    else:
        print('  [-] Error getting drivers from: {url}')
    return result


def lol_vulnerable_driver_parser(data):
    driver_list = []
    hash_list = []
    for entry in data:
        tag_list = entry.get('Tags')
        for tag in tag_list:
            if tag.endswith('.sys'):
                driver_list.append(tag[:-4])
                sample_list = entry.get('KnownVulnerableSamples')
                for sample in sample_list:
                    sample_sha256 = sample.get('SHA256')
                    if sample_sha256:
                        hash_list.append(sample_sha256)
    return (driver_list, hash_list)


def microsoft_driver_parser(data):
    driver_list = []
    for line in data:
        drivers = line.split()
        for driver in drivers:
            if 'FileName' in driver:
                driver_list.append(driver[10:])
        final_driver_list = []
        for driver in driver_list:
                if '.'  or '\"'in driver:
                    index = driver.find('.')
                    final_driver_list.append(driver[:index])
                else:
                    final_driver_list.append(driver)
    return final_driver_list[2:]

def windows_hash_parser(data):
    hash_list = []
    for line in data:
        hashes = line.split()
        for hash in hashes:
            if 'Hash' in hash:
                hash_list.append(hash[6:])
    for hash in hash_list:
        if len(hash) == 0:
            hash_list.remove(hash)
    hash_list_2 = []
    for hash in hash_list:
        if '\"' in hash:
            index = hash.find("\"")
            hash_list_2.append(hash[:index])
        else:
            hash_list_2.append(hash)
    lower_case_hashes = [hash.lower() for hash in hash_list_2]
    hash_list = lower_case_hashes
    return hash_list

def query_and_parse_host_drivers(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        driver_names =  [line.split() [0] for line in output_lines if line.strip()]
        return driver_names [2:]
    except subprocess.CalledProcessError as e:
        print(f"  [-] Error executing driverquery command: {e}")
        return ""

def lists_to_dict(keys, values):
    return dict(zip(keys, values))

# 드라이버 경로 찾기 함수
def driver_path_finder(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        paths = []
        for line, slice in enumerate(output_lines):
            for index in range(len(slice) - 1):
                if slice[index:index + 2] == 'C:':
                    path = output_lines[line][index:]
                    paths.append(path)
        return paths
    except subprocess.CalledProcessError as e:
        print(f"  [-] Error executing driverquery command: {e}")
        return ""

def hash_host_drivers(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        driver_hash = output_lines[1]
        return driver_hash
    except subprocess.CalledProcessError:
        pass

#for문으로 변경 -> 매치하는거 전역변수로 저장, 불리스트로 비교할 수 있게
#def find_matches(vulnerable_drivers, host_drivers):
#    unique_vulnerable_drivers = set(vulnerable_drivers)
#    unique_host_drivers = set(host_drivers)
#    matches = list(unique_vulnerable_drivers.intersection(unique_host_drivers))
#    return matches

#matches 구현?
def find_match_hashes(vulnerable_drivers, host_drivers):
    matches = []
    for i in range(len(host_drivers)):
        for j in range(len(vulnerable_drivers)):
            if(host_drivers[i] == vulnerable_drivers[j]):
                matches.append(vulnerable_drivers[j])
    return matches

def find_match_names(vulnerable_drivers, host_driver_paths):
    matches = []
    for i in range(len(host_driver_paths)):
        name = host_driver_paths[i].split('\\')[-1][:-4]
        for j in range(len(vulnerable_drivers)):
            if(name == vulnerable_drivers[j]):
                matches.append(host_driver_paths[j])
    return matches

def os_compatability_check():
    os_platform = sys.platform
    os_name = os.name
    if os_name != 'nt' or not os_platform.startswith('win'):
        print(f'[-] Error! the OS name:{os_name} or OS type:{os_platform} does not appear to be windows')
        exit(1)

def display(matching_drivers):

    if len(matching_drivers):
        print(f'  [!] VULNERABLE DRIVERS DETECTED')
        time.sleep(2)

        for match in matching_drivers:
            name = match.split('\\')[-1]
            print(f'  \t[-] Vulnerable Driver: {name}')
            time.sleep(0.2)

        time.sleep(0.2)
        print(f'  [*] Drivers can be stopped by using the \"sc stop <driver>\" command when executed with administrative privileges')

        time.sleep(0.2)
        print(f'  [*] Drivers can be deleted by using the \"sc delete <driver>\" command when executed with administrative privileges')

        time.sleep(0.2)
        print(f'  [*] Check for false positives by verifying the version of the vulnerable driver')

        time.sleep(0.2)
        print(f'  [*] Run this powershell command to check all driver versions')

        time.sleep(0.2)
        print(r'  [*] Get-WmiObject Win32_PnPSignedDriver | Select-Object -Property DeviceName, DriverVersion ; Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like "PCI\VEN_*" } | Select-Object -Property Name, DriverVersion')

        time.sleep(0.2)
        print(f'  [*] Use a 3rd party to verify host driver hash and act accordingly')

        time.sleep(0.2)
    else:
        print(f'  [+] No vulnerable drivers detected on your machine')

def main():
    welcome()
    time.sleep(1)
    os_compatability_check()

    try:
        print(f'\n\n  [+] Querying host drivers')
        time.sleep(2)

        host_drivers = query_and_parse_host_drivers('driverquery /v')

        print(f'  [+] Hashing all local system drivers')
        time.sleep(2)

        host_driver_paths = driver_path_finder('driverquery /FO list /v')

        host_driver_hashes = []

        for path in host_driver_paths:
            driver_hash = hash_host_drivers( f'certutil -hashfile {path} SHA256')
            host_driver_hashes.append(driver_hash)

        hash_dictionary = lists_to_dict(host_driver_hashes, host_drivers)

        print(f'  [+] Query API for updated vulnerable driver list & corresponding SHA 256 hashes from https://www.loldrivers.io/api/drivers.json')
        time.sleep(2)

        data = get_json_endpoint('https://www.loldrivers.io/api/drivers.json')
        (lol_vuln_driver_list, lol_driver_hashes) = lol_vulnerable_driver_parser(data)

        print(f'  [+] Web scraping updated vulnerable driver list & corresponding SHA 256 hashes from https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules')
        time.sleep(2)

        data = web_scrape_and_process('https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules','lang-xml')
        windows_vuln_driver_list = microsoft_driver_parser(data)
        windows_hashes = windows_hash_parser(data)

        print(f'  [*] Checking vulnerable drivers through name matching & hash based detection')
        time.sleep(2)

        for i in range(len(host_driver_paths)):
            match_res.append('0')

        matching_lol_drivers = find_match_names(lol_vuln_driver_list, host_driver_paths)
        matching_lol_hashes = find_match_hashes(lol_driver_hashes, host_driver_hashes)

        matching_windows_drivers = find_match_names(windows_vuln_driver_list, host_driver_paths)
        matching_windows_hashes = find_match_hashes(windows_hashes, host_driver_hashes)

        matching_drivers = []
        if (matching_lol_drivers) :
            matching_drivers += matching_lol_drivers
        if (matching_windows_drivers) :
            matching_drivers += matching_windows_drivers
        
        if len(matching_lol_hashes):
            print(f'  [!] HASH BASED DETECTION')
            time.sleep(2)
            for hash in matching_lol_hashes:
                driver = hash_dictionary[hash]
                matching_drivers.append(driver)
        if len(matching_windows_hashes):
            print(f'  [!] HASH BASED DETECTION')
            time.sleep(2)
            for hash in matching_windows_hashes:
                driver = hash_dictionary[hash]
                matching_drivers.append(driver)

        display(matching_drivers)
        time.sleep(3)
        
        with open(".\\Primary_Examination_result.csv", "w") as first_f :
            w = csv.writer(first_f)
            result = ["Driver Name", "Full Path"]
            w.writerow(result)

            for driver in matching_drivers :
                result[0] = driver.split('\\')[-1]
                result[1] = driver
                w.writerow(result)

        for driver in matching_drivers :
            helper(driver)

        print("\n\n")
        print('======= Vulnerable Driver Scanning Finished =======')
        print(f'We found {len(matching_drivers)} vulnerable drivers')
        print("Please refer to the output file for detailed test results.\n\n")
            

    except (ConnectionError, RequestException) as e:
        time.sleep(1)
        print(f'  [-] An error occurred while trying to establish a secure connection. Please check your internet connection and try again later.\n')
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()


# paths -> drvr path -> remain
#