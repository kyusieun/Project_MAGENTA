// �� �Լ��� ���� (������ ������ �ۼ��� �ּ���)
#include <windows.h>
#include "./kdmapper/kdmain.hpp"
#include "./gdrvmapper/gdmain.hpp"

void DSEFixMapping() {
	gdmain();
}
int FixedImageMapping() {
	return kdmain();
}
void MSRExec() {};
void LargePageMapping() {};
void IORingExec() {};

void print_help();
void print_choice();
