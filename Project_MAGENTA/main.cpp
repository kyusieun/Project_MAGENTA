#include "include/dseFix/dseFix.hpp"
#include "include/common_header.h"

std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// 전역 변수
std::string target_driver;


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <target_driver_path>" << std::endl;
        return 1;
    }

    // 타겟 드라이버 경로를 전역 변수에 저장
    target_driver = argv[1];
    std::cout << "Target Driver: " << target_driver << std::endl;

    // 매핑 방식 선택
    int choice;
    std::cout << "Select a mapping method:\n";
    std::cout << "1. DSE Fix\n";
    std::cout << "2. Fixed Image\n";
    std::cout << "3. MSR\n";
    std::cout << "4. LP\n";
    std::cout << "5. I/O Ring\n";
    std::cout << "Enter your choice (1-5): ";
    std::cin >> choice;

    // 선택된 매핑 방식 실행
    switch (choice) {
    case 1:
        DSEFixRun(target_driver);
        break;
    /*case 2:
        FixedImage();
        break;
    case 3:
        MSR();
        break;
    case 4:
        LPmapper();
        break;
    case 5:
        IORing();
        break;*/
    default:
        std::cerr << "Invalid choice. Please enter a number between 1 and 5." << std::endl;
        return 1;
    }

    return 0;
}

//// 각각 ~.cpp 파일에 정의하시고, ~.hpp 파일에 선언해주세요
//void FixedImageRun(target_driver) {
//    std::cout << "Executing Fixed Image routine..." << std::endl;
//    // 여기에 Fixed Image 루틴을 구현
//}
//
//void MsrRun(target_driver) {
//    std::cout << "Executing MSR routine..." << std::endl;
//    // 여기에 MSR 루틴을 구현
//}
//
//void LPmapperRun(target_driver) {
//    std::cout << "Executing LP routine..." << std::endl;
//    // 여기에 LP 루틴을 구현
//    // lp git test
//}
//
//void IORingRun(target_driver) {
//    std::cout << "Executing I/O Ring routine..." << std::endl;
//    // 여기에 I/O Ring 루틴을 구현
//}
