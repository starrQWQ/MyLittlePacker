/*********************************************
*	v1.5
*	Compress .text
************************************************/


#include <windows.h>
#include <stdio.h>
#include "MyPack.h"

int main(int argc, char* argv[])
{
	/*MyPack::Pack("../exe/CTest.exe", NULL) == -1 ?
		MessageBoxA(NULL, "Failed", "ERROR", 0)
		: MessageBoxA(NULL, "Packing Finished", "Success", 0);*/
	
	if (1 == argc)
	{
		printf("USAGE: MyPack EXE_PATH [PASSWORD] ");
	}
	else if (2 == argc)
	{
		MyPack::Pack(argv[1], NULL) == -1 ?
			MessageBoxA(NULL, "Failed", "ERROR", 0)
			: MessageBoxA(NULL, "Packing Finished", "Success", 0);
	}
	else if (3 == argc)
	{
		MyPack::Pack(argv[1], argv[2]) == -1 ?
			MessageBoxA(NULL, "Failed", "ERROR", 0)
			: MessageBoxA(NULL, "Packing Finished", "Success", 0);
	}

	return 0;
}