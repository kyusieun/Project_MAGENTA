// �� �Լ��� ���� (������ ������ �ۼ��� �ּ���)
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
