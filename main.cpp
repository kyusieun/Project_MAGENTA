#include <iostream>
#include <stdexcept>
#include "main.hpp"

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
            std::cout << "Executing I/O Ring Exec..." << std::endl;
            IORingExec();
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

int main() {
    int choice;

    std::cout << "Select a function to execute:" << std::endl;
    std::cout << "1. DSEFix Mapping" << std::endl;
    std::cout << "2. Fixed Image Mapping" << std::endl;
    std::cout << "3. MSRExec" << std::endl;
    std::cout << "4. LargePageMapping" << std::endl;
    std::cout << "5. I/O Ring Exec" << std::endl;
    std::cout << "Enter your choice (1-5): ";
    std::cin >> choice;

    ExecuteFunction(choice);

    return 0;
}

