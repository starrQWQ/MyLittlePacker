// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <windows.h>
#include "lz4.h"

/*********************************************
*	v1.5
*
************************************************/

#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")


/*******************
*	v1.5 modified
********************/
typedef struct _SHAREDDATA
{
	DWORD dwEncRVA;
	DWORD dwEncSize;
	BYTE key;

	DWORD dwOldOEP;

	/******************
	*	IID info at
	*  DataDir[1]
	*******************/
	DWORD dwIIDRVA;
	DWORD dwIIDSize;


	/*******************
	*	v1.2
	*	DataDir[5]
	******************/
	DWORD dwRelocRVA;
	DWORD dwRelocSize;
	DWORD dwTextRVA;
	DWORD dwTextSize;
	DWORD dwStubRVA;
	DWORD dwDefImageBase;

	/******************
	*	v1.3
	*	password
	******************/
	char szPassword[20];

	/*************
	*	v1.5
	***************/
	DWORD dwCompressRVA;
	DWORD dwCompressSizeBefore;
	DWORD dwCompressSizeAfter;


}SHAREDDATA, * PSHAREDDATA;

/******************
*	v1.2 added
*********************/
typedef struct _TypeOffset
{
	WORD offset : 12;
	WORD type : 4;
}TypeOffset, * PTypeOffset;

/***********************
*	Function pointers
************************/

decltype(GetProcAddress)* pGetProcAddress = nullptr;
decltype(VirtualProtect)* pVirtualProtect = nullptr;
decltype(LoadLibraryA)* pLoadLibraryA = nullptr;
decltype(GetModuleHandleA)* pGetModuleHandleA = nullptr;
decltype(HeapCreate)* pHeapCreate = nullptr;
decltype(HeapAlloc)* pHeapAlloc = nullptr;

/********* v1.3 added **********/
decltype(RegisterClassA)* pRegisterClassA = nullptr;
decltype(CreateWindowExA)* pCreateWindowExA = nullptr;
decltype(ShowWindow)* pShowWindow = nullptr;
decltype(UpdateWindow)* pUpdateWindow = nullptr;
decltype(GetMessageA)* pGetMessageA = nullptr;
decltype(TranslateMessage)* pTranslateMessage = nullptr;
decltype(DispatchMessageA)* pDispatchMessageA = nullptr;
decltype(GetWindowTextA)* pGetWindowTextA = nullptr;
decltype(DestroyWindow)* pDestroyWindow = nullptr;
decltype(PostQuitMessage)* pPostQuitMessage = nullptr;
decltype(DefWindowProcA)* pDefWindowProcA = nullptr;
decltype(ExitProcess)* pExitProcess = nullptr;


/*************************
*	stub(.text)
**************************/
extern "C"
{
	__declspec(dllexport) SHAREDDATA sharedData;

	__declspec(naked) DWORD GetKernelBase()
	{
		__asm {
			mov eax, dword ptr fs : [0x30] ;
			mov eax, [eax + 0x0c];
			mov eax, [eax + 0x1c];
			mov eax, [eax];
			mov eax, [eax + 0x08];
			ret;
		}
	}

	/***********************
	*	v1.3 added
	************************/
	__declspec(naked) DWORD GetCurMod()
	{
		__asm {
			mov eax, dword ptr fs : [0x30] ;
			mov eax, [eax + 0x08];
			ret
		}
	}

	DWORD MyGetProcAddress(DWORD hMod, LPCSTR lpFuncName)
	{
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
		PIMAGE_NT_HEADERS32 pNt = (PIMAGE_NT_HEADERS32)((DWORD)pDos + pDos->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 pOpt = &(pNt->OptionalHeader);
		PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)(pOpt->DataDirectory[0].VirtualAddress + (DWORD)pDos);

		DWORD* pAddr = (DWORD*)((DWORD)pDos + pIED->AddressOfFunctions);
		DWORD* pName = (DWORD*)((DWORD)pDos + pIED->AddressOfNames);
		WORD* pOrd = (WORD*)((DWORD)pDos + pIED->AddressOfNameOrdinals);

		for (DWORD i = 0; i < pIED->NumberOfNames; ++i)
		{
			if (!strcmp(lpFuncName,
				(const char*)((DWORD)pDos + pName[i])))
			{
				return (pAddr[pOrd[i]] + (DWORD)pDos);
			}
		}

		return -1;
	}


	void GetAPI()
	{
		char modName[][20] = {
			{ 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' },
			{"user32.dll"}
		};
		char funcName[][20] = {
			{'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0'},
			{'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0'},
			{'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c','t','\0'},
			{'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', '\0'},
			{'H', 'e', 'a', 'p', 'C', 'r', 'e', 'a', 't', 'e', '\0'},
			{'H', 'e', 'a', 'p', 'A', 'l', 'l', 'o', 'c', '\0'},
			{"RegisterClassA"},
			{"CreateWindowExA"},
			{"ShowWindow"},
			{"UpdateWindow"},
			{"GetMessageA"},
			{"TranslateMessage"},
			{"DispatchMessageA"},
			{"GetWindowTextA"},
			{"DestroyWindow"},
			{"PostQuitMessage"},
			{"DefWindowProcA"},
			{"ExitProcess"}
		};
		pLoadLibraryA = (decltype(LoadLibraryA)*)MyGetProcAddress(GetKernelBase(), funcName[0]);
		pGetProcAddress = (decltype(GetProcAddress)*)MyGetProcAddress(GetKernelBase(), funcName[1]);

		HMODULE hKer = pLoadLibraryA(modName[0]);
		HMODULE hUser = pLoadLibraryA(modName[1]);

		pVirtualProtect = (decltype(VirtualProtect)*)pGetProcAddress(hKer, funcName[2]);
		pGetModuleHandleA = (decltype(GetModuleHandleA)*)pGetProcAddress(hKer, funcName[3]);
		pHeapCreate = (decltype(HeapCreate)*)pGetProcAddress(hKer, funcName[4]);
		pHeapAlloc = (decltype(HeapAlloc)*)pGetProcAddress(hKer, funcName[5]);

		/********* v1.3 added **********/
		pRegisterClassA = (decltype(RegisterClassA)*)pGetProcAddress(hUser, funcName[6]);
		pCreateWindowExA = (decltype(CreateWindowExA)*)pGetProcAddress(hUser, funcName[7]);
		pShowWindow = (decltype(ShowWindow)*)pGetProcAddress(hUser, funcName[8]);
		pUpdateWindow = (decltype(UpdateWindow)*)pGetProcAddress(hUser, funcName[9]);
		pGetMessageA = (decltype(GetMessageA)*)pGetProcAddress(hUser, funcName[10]);
		pTranslateMessage = (decltype(TranslateMessage)*)pGetProcAddress(hUser, funcName[11]);
		pDispatchMessageA = (decltype(DispatchMessageA)*)pGetProcAddress(hUser, funcName[12]);
		pGetWindowTextA = (decltype(GetWindowTextA)*)pGetProcAddress(hUser, funcName[13]);
		pDestroyWindow = (decltype(DestroyWindow)*)pGetProcAddress(hUser, funcName[14]);
		pPostQuitMessage = (decltype(PostQuitMessage)*)pGetProcAddress(hUser, funcName[15]);
		pDefWindowProcA = (decltype(DefWindowProcA)*)pGetProcAddress(hUser, funcName[16]);
		pExitProcess = (decltype(ExitProcess)*)pGetProcAddress(hKer, funcName[17]);
	}


	int DecryptText()
	{
		DWORD dwOldProtect = 0;
		DWORD dwVA = sharedData.dwEncRVA;
		// Get ImageBase
		__asm {
			mov ebx, dword ptr fs : [0x30] ;
			mov ebx, [ebx + 0x08];
			add dwVA, ebx;
		}

		pVirtualProtect((LPVOID)dwVA, sharedData.dwEncSize, PAGE_READWRITE, &dwOldProtect);

		BYTE* pData = (BYTE*)dwVA;
		for (DWORD i = 0; i < sharedData.dwEncSize; ++i)
		{
			pData[i] ^= sharedData.key;
		}

		pVirtualProtect((LPVOID)dwVA, sharedData.dwEncSize, dwOldProtect, &dwOldProtect);

		return 0;
	}


	// jmp to original OEP
	__declspec(naked) void jmpOEP()
	{
		_asm {
			mov ebx, dword ptr fs : [0x30] ;
			mov ebx, [ebx + 0x08];
			add ebx, sharedData.dwOldOEP;
			jmp ebx;
		}
	}

	/**************************
	*	v1.1 Build a fake IAT
	***************************/
	int ProcessIAT()
	{
		char szShellcode[] = { "\xE8\x01\x00\x00\x00\xE9\x83\xC4\x04\xEB\x01\xC3\x68\x44\x33\x22\x11\xC3\x90" };
		// *(DWORD*)&shellcode[13] : func addr in IAT

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pGetModuleHandleA(NULL);
		PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)
			(sharedData.dwIIDRVA + (DWORD)pDos);

		PIMAGE_THUNK_DATA32 pINT = nullptr, pIAT = nullptr;
		PIMAGE_IMPORT_BY_NAME pName = nullptr;
		char* pDllName = nullptr;


		HMODULE hMod = nullptr;
		DWORD dwFunc = 0;

		HANDLE hHeap = pHeapCreate(0, 0, 0);
		LPVOID lpShellcode = nullptr;

		DWORD dwOldProtect = 0;
		while (pIID->Name)
		{
			pDllName = (char*)((DWORD)pDos + pIID->Name);
			hMod = pLoadLibraryA(pDllName);

			pINT = (PIMAGE_THUNK_DATA32)((DWORD)pDos + pIID->OriginalFirstThunk);
			pIAT = (PIMAGE_THUNK_DATA32)((DWORD)pDos + pIID->FirstThunk);

			while (pINT->u1.Ordinal)
			{
				if (!(pINT->u1.Ordinal &
					(1 << (8 * sizeof(pIAT->u1.Ordinal) - 1))))
				{
					pName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDos + pINT->u1.Ordinal);

					dwFunc = (DWORD)pGetProcAddress(hMod, pName->Name);

					*(DWORD*)&szShellcode[13] = dwFunc;

					lpShellcode = pHeapAlloc(hHeap, HEAP_ZERO_MEMORY, 20);
					memcpy(lpShellcode, szShellcode, 18);

					pVirtualProtect(pIAT, 0x1000, PAGE_READWRITE, &dwOldProtect);
					pIAT->u1.Function = (DWORD)lpShellcode;
					pVirtualProtect(pIAT, 0x1000, dwOldProtect, &dwOldProtect);

					pVirtualProtect(lpShellcode, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
				}

				++pINT;
				++pIAT;
			}


			++pIID;
		}

		return 0;
	}


	/*******************************
	*	v1.2
	*	Repair EXE .text
	********************************/
	void RepairTextReloc()
	{
		DWORD dwImageBase = 0;
		__asm {
			mov edx, dword ptr fs : [0x30] ;
			mov edx, [edx + 0x08];
			mov dwImageBase, edx;
		}
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(sharedData.dwRelocRVA + dwImageBase);

		DWORD dwVA = pReloc->VirtualAddress + dwImageBase;
		PDWORD pdwTarget = NULL;
		DWORD dwCount = 0;
		PTypeOffset pTypeOffset = NULL;
		DWORD dwTmp = 0;
		DWORD dwOldProtect = 0;
		while (pReloc->SizeOfBlock)
		{

			dwCount = (pReloc->SizeOfBlock - 8) / 2;
			pTypeOffset = (PTypeOffset)(pReloc + 1);

			pVirtualProtect(
				(LPVOID)(dwImageBase + pReloc->VirtualAddress),
				0x2000,
				PAGE_READWRITE,
				&dwOldProtect);

			for (DWORD i = 0; i < dwCount; ++i)
			{
				if (pTypeOffset->type == 3)
				{
					pdwTarget = (PDWORD)
						(dwImageBase
							+ pReloc->VirtualAddress
							+ pTypeOffset->offset);
					dwTmp =
						*pdwTarget
						- sharedData.dwDefImageBase
						- sharedData.dwTextRVA;
					*pdwTarget =
						dwImageBase
						+ sharedData.dwTextRVA
						+ dwTmp;
					++pTypeOffset;
				}
			}

			pVirtualProtect(
				(LPVOID)(dwImageBase + pReloc->VirtualAddress),
				0x2000,
				dwOldProtect,
				&dwOldProtect);

			pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);

		}
	}


	/*******************************
	*	v1.3
	*	SDK: Input password
	***************************************/
	HWND g_hEditWnd = NULL;
	LRESULT CALLBACK wndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)

	{

		switch (uMsg)
		{
		case WM_CREATE:
		{
			g_hEditWnd = pCreateWindowExA(0, "EDIT", "Input Password(<20)",
				WS_CHILD | WS_BORDER | WS_VISIBLE,
				40, 50, 140, 20,
				hWnd,
				NULL, NULL, NULL
			);


			HWND hBtnWnd = pCreateWindowExA(0, "BUTTON", "unpack",
				WS_CHILD | WS_BORDER | WS_VISIBLE,
				60, 80, 60, 20,
				hWnd,
				(HMENU)0x1001, NULL, NULL
			);
			break;
		}
		case WM_CLOSE:
		{
			pExitProcess(0);
			break;
		}

		case WM_COMMAND:
		{
			if (0x1001 == wParam)
			{
				char buf[20] = { 0 };
				pGetWindowTextA(g_hEditWnd, buf, 20);
				if (!strcmp(buf, sharedData.szPassword))
				{
					pDestroyWindow(hWnd);
					pPostQuitMessage(0);

				}
			}
			break;
		}
		}
		return pDefWindowProcA(hWnd, uMsg, wParam, lParam);
	}
	void InputPassword()

	{
		WNDCLASSA wndClsA = { 0 };

		wndClsA.hInstance = (HINSTANCE)GetCurMod();
		wndClsA.lpszClassName = "password";
		wndClsA.lpfnWndProc = wndProc;

		pRegisterClassA(&wndClsA);

		HWND hWnd = pCreateWindowExA(
			0,
			"password",
			"",
			WS_OVERLAPPEDWINDOW | WS_VISIBLE,
			100, 100, 300, 200,
			NULL,
			NULL,
			(HINSTANCE)GetCurMod(),
			NULL
		);

		pShowWindow(hWnd, SW_SHOW);
		pUpdateWindow(hWnd);

		MSG msg;
		while (pGetMessageA(&msg, NULL, 0, 0))
		{
			pTranslateMessage(&msg);
			pDispatchMessageA(&msg);
		}

		return;
	}

	/*******************************
	*	v1.3
	*	AntiDebug
	***************************************/
	BOOL BeingDebugged()
	{
		__asm {
			mov eax, dword ptr fs : [0x30]
			movzx eax, dword ptr[eax + 0x02];
		}
	}

	/*********************************************
	*	v1.5
	*	Compress .text
	************************************************/
	/*void MyMemCpy(char* pDst, char* pSrc, size_t  size)
	{
		for (size_t i = 0; i < size; ++i)
		{
			pDst[i] = pSrc[i];
		}
	}*/
	void UncompressSection()
	{
		char* pTarget = (char*)(sharedData.dwCompressRVA + GetCurMod());
		HANDLE hHeap = pHeapCreate(0, 0, 0);
		char* pBuf = (char*)pHeapAlloc(hHeap, HEAP_ZERO_MEMORY, sharedData.dwCompressSizeBefore);
		LZ4_decompress_safe(
			pTarget,
			pBuf,
			sharedData.dwCompressSizeAfter,
			sharedData.dwCompressSizeBefore);

		DWORD dwOldProtect = 0;
		pVirtualProtect(pTarget, sharedData.dwCompressSizeBefore, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		//memcpy(pTarget, pBuf, sharedData.dwCompressSizeBefore);
		for (size_t i = 0; i < sharedData.dwCompressSizeBefore; ++i)
		{
			pTarget[i] = pBuf[i];
		}
		pVirtualProtect(pTarget, sharedData.dwCompressSizeBefore, dwOldProtect, &dwOldProtect);

	}


	__declspec(dllexport) __declspec(naked) void start()
	{
		GetAPI();
		if (sharedData.szPassword[0])
		{
			InputPassword();
		}
		if (BeingDebugged()) pExitProcess(0);

		DecryptText();
		UncompressSection();


		ProcessIAT();
		RepairTextReloc();

		jmpOEP();
	}
}
