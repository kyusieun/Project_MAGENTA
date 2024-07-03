#include <iostream>
#include <stdexcept>
#include "main.hpp"
#include "logo.hpp"

class FunctionExecutionException : public std::runtime_error {
public:
    explicit FunctionExecutionException(const std::string& message)
        : std::runtime_error(message) {}
};

// 사용자가 선택한 함수를 실행하는 함수
void ExecuteFunction(int choice) {
    try {
        switch (choice) {
        case 1:
            std::cout << "Executing DSEFix Mapping..." << std::endl;
            DSEFixMapping();
            break;
        case 2:
            std::cout << "Executing Fixed Image Mapping..." << std::endl;
            FixedImageMapping();
            break;
        case 3:
            std::cout << "Executing MSRExec..." << std::endl;
            MSRExec();
            break;
        case 4:
            std::cout << "Executing LargePageMapping..." << std::endl;
            LargePageMapping();
            break;
        case 5:
            print_help();
            break;
        default:
            throw FunctionExecutionException("Invalid choice! Please enter a number between 1 and 5.");
        }
        std::cout << "Function executed successfully." << std::endl;
    }
    catch (const FunctionExecutionException& ex) {
        std::cerr << "Function execution failed: " << ex.what() << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << "An error occurred: " << ex.what() << std::endl;
    }
}

void print_help()
{
    std::string DSEFix_help = "This checks if the g_CiOptions flag can be modified to enable loading unauthorized drivers after activating Windows Test Mode without a system reboot. This vulnerability can occur if kernel-level memcpy is possible.";
    std::string FixedMapping_help = "This checks if the read/write capabilities of a vulnerable driver's physical memory can be exploited to forcibly load unauthorized drivers into kernel memory. This vulnerability can occur if a driver that provides access to physical memory can be loaded.";
    std::string MSRExec_help = "This checks if the MSRs used for syscall invocation can be manipulated. This vulnerability can occur if a vulnerable driver that provides the wrmsr functionality for interacting with MSRs can be loaded.";
    std::string LPMapping_help = "This checks if the .data section of Windows system drivers can be manipulated into an executable form. This vulnerability can occur if a Windows system driver can be loaded into large page memory.";

    std::cout << "\n\n================ Help ================\n";
    std::cout << "1. DSEFix Mapping : \n" << DSEFix_help << "\n\n";
    std::cout << "2. Fixed Image Mapping : \n" << FixedMapping_help << "\n\n";
    std::cout << "3. MSRExec Mapping : \n" << MSRExec_help << "\n\n";
    std::cout << "4. Large Page Mapping : \n" << LPMapping_help << "\n\n";
    std::cout << "======================================\n\n";

    int choice;
    print_choice();
    std::cin >> choice;
    ExecuteFunction(choice);
}

void print_choice()
{
    std::cout << "Select a function to execute:" << std::endl;
    std::cout << "1. DSEFix Mapping" << std::endl;
    std::cout << "2. Fixed Image Mapping" << std::endl;
    std::cout << "3. MSRExec" << std::endl;
    std::cout << "4. LargePageMapping" << std::endl;
    std::cout << "5. Help" << std::endl;
    std::cout << "Enter your choice (1-5): ";
}

int main() {
    int choice;

    std::cout << logo << std::endl;
    std::cout << "===== Welcome to [Penetrate Your Own Vulneravle Driver] =====" << std::endl;
    std::cout << "This tool checks if your system has vulnerabilities that could lead to a BYOVD attack." << std::endl;

    print_choice();
    std::cin >> choice;

    ExecuteFunction(choice);

    return 0;
}

