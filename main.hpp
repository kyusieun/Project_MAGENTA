// 각 함수의 선언 (구현은 별도로 작성해 주세요)
#include <windows.h>
#include "./kdmapper/kdmain.hpp"
#include "./gdrvmapper/gdmain.hpp"
#include "./wrmsr/msrmain.hpp"

void DSEFixMapping() {
	gdmain();
}
int FixedImageMapping() {
	return kdmain();
}
void MSRExec() {
	msrmain();
}
void LargePageMapping() {};
void IORingExec() {};
