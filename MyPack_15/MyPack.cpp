#include <time.h>
#include "MyPack.h"
#include "lz4.h"
/*********************************************
*	v1.4

**********************************************/




/***********************
*	v0.3 added
***********************/
typedef struct _TypeOffset
{
	WORD offset : 12;
	WORD type : 4;
}TypeOffset, * PTypeOffset;

DWORD MyPack::dwFileSize = 0;
PIMAGE_DOS_HEADER MyPack::pExeDos = NULL;
PIMAGE_DOS_HEADER MyPack::pDllDos = NULL;
PSHAREDDATA MyPack::pSharedData = NULL;

inline PIMAGE_NT_HEADERS32 MyPack::GetNtHeader32(PIMAGE_DOS_HEADER pDos)
{
	return (PIMAGE_NT_HEADERS32)((ULONGLONG)pDos + pDos->e_lfanew);
}

inline PIMAGE_FILE_HEADER MyPack::GetFileHeader(PIMAGE_DOS_HEADER pDos)
{
	return (PIMAGE_FILE_HEADER) & (GetNtHeader32(pDos)->FileHeader);
}

inline PIMAGE_OPTIONAL_HEADER32 MyPack::GetOptHeader32(PIMAGE_DOS_HEADER pDos)
{
	return (PIMAGE_OPTIONAL_HEADER32) & (GetNtHeader32(pDos)->OptionalHeader);
}

DWORD MyPack::Alignment(DWORD dwSize, DWORD dwAlignment)
{
	DWORD dwRet = (dwSize % dwAlignment == 0) ? dwSize
		: (dwSize / dwAlignment + 1) * dwAlignment;
	return dwRet;
}

int MyPack::LoadFiles(LPCSTR lpFileName, LPCSTR lpDllName)
{
	// 1. If the file exists...
	HANDLE hPE = CreateFileA(lpFileName, GENERIC_READ, NULL, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hPE == INVALID_HANDLE_VALUE) return -1;

	dwFileSize = GetFileSize(hPE, NULL);
	pExeDos = (PIMAGE_DOS_HEADER)calloc(1, dwFileSize);

	if (!ReadFile(hPE, pExeDos, dwFileSize, NULL, NULL)) return -1;

	CloseHandle(hPE);


	// 2. Load dll which contains stub 
	pDllDos = (PIMAGE_DOS_HEADER)LoadLibraryExA(lpDllName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!pDllDos) return -1;

	/************************
	*	v0.3 added
	***********************/
	pSharedData = (PSHAREDDATA)GetProcAddress((HMODULE)pDllDos, "sharedData");

	return 0;
}

int MyPack::Release()
{
	if (pExeDos)
	{
		free(pExeDos);
		pExeDos = nullptr;
	}

	if (pDllDos)
	{
		pDllDos = nullptr;
	}

	dwFileSize = 0;
	pSharedData = nullptr;

	return 0;
}

int MyPack::CopySectionHeader(LPCSTR pNewSectionName, LPCSTR pFromSectionName/* = ".text"*/)

{
	// 1. Get the last section header
	PIMAGE_SECTION_HEADER pLastSectionHeader = (PIMAGE_SECTION_HEADER)
		((ULONGLONG)IMAGE_FIRST_SECTION(GetNtHeader32(pExeDos))
			+ (GetFileHeader(pExeDos)->NumberOfSections - 1)
			* sizeof(IMAGE_SECTION_HEADER));

	// 2. ++NumberOfSection
	++(GetFileHeader(pExeDos)->NumberOfSections);

	// 3. Get new section header, and memset to 0
	PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)
		((ULONGLONG)pLastSectionHeader + sizeof(IMAGE_SECTION_HEADER));
	memset(pNewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));

	// 4. Get stub section from dll 
	PIMAGE_SECTION_HEADER pStubSectionHeader = GetSectionHeader(pDllDos, pFromSectionName);
	// 5. Memcpy to new section
	memcpy(pNewSectionHeader, pStubSectionHeader, sizeof(IMAGE_SECTION_HEADER));

	// 6. Set new section name
	memcpy(pNewSectionHeader->Name, pNewSectionName, IMAGE_SIZEOF_SHORT_NAME - 1);


	// 5. Set section attribute, RWE | containing code | containing initialized/uninitialized  data 
	pNewSectionHeader->Characteristics = 0xE00000E0;

	// 6. Set RVA = last section RVA + last section vsize aligned
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress
		+ Alignment(pLastSectionHeader->Misc.VirtualSize, GetOptHeader32(pExeDos)->SectionAlignment);

	// 7. Set FOA = last section FOA + last section rsize aligned
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData
		+ Alignment(pLastSectionHeader->SizeOfRawData, GetOptHeader32(pExeDos)->FileAlignment);

	// 9. realloc
	dwFileSize = pNewSectionHeader->PointerToRawData + pNewSectionHeader->SizeOfRawData;
	pExeDos = (PIMAGE_DOS_HEADER)realloc(pExeDos, dwFileSize);
	if (!pExeDos) return -1;

	// 10. Modify ImageBase
	GetOptHeader32(pExeDos)->SizeOfImage = pNewSectionHeader->VirtualAddress + pNewSectionHeader->Misc.VirtualSize;

	/**********************
	* v0.3 deleted

	LPVOID pStubSection = (LPVOID)(pStubSectionHeader->VirtualAddress + (DWORD)pDllDos);
	LPVOID pNewSection = (LPVOID)(pNewSectionHeader->PointerToRawData + (DWORD)pExeDos);
	memcpy(pNewSection, pStubSection, pStubSectionHeader->SizeOfRawData);

	***********************/

	return 0;
}

int MyPack::CopySectionBody(LPCSTR pNewSectionName, LPCSTR pFromSectionName)
{
	PIMAGE_SECTION_HEADER pStubSectionHeader = GetSectionHeader(pDllDos, pFromSectionName);
	PIMAGE_SECTION_HEADER pNewSectionHeader = GetSectionHeader(pExeDos, pNewSectionName);

	LPVOID pStubSection = (LPVOID)(pStubSectionHeader->VirtualAddress + (DWORD)pDllDos);
	LPVOID pNewSection = (LPVOID)(pNewSectionHeader->PointerToRawData + (DWORD)pExeDos);

	memcpy(pNewSection, pStubSection, pStubSectionHeader->SizeOfRawData);
	return 0;
}

int MyPack::FixRelocTable(LPCSTR lpStubSectionName, LPCSTR lpFixSectionName /* = ".text"*/)
{
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(GetSectionHeader(pDllDos, ".reloc")->VirtualAddress + (DWORD)pDllDos);
	DWORD dwCount = 0;
	DWORD dwOldProtect = 0;
	DWORD dwTmp = 0;
	PDWORD pdwTarget = 0;
	PTypeOffset pTypeOffset = NULL;
	while (pReloc->SizeOfBlock)
	{
		dwCount = (pReloc->SizeOfBlock - 8) / 2;
		pTypeOffset = (PTypeOffset)(pReloc + 1);

		VirtualProtect((LPVOID)(pReloc->VirtualAddress + (DWORD)pDllDos), 0x1000, PAGE_READWRITE, &dwOldProtect);

		for (DWORD i = 0; i < dwCount; ++i, ++pTypeOffset)
		{
			if (pTypeOffset->type == 3)
			{

				pdwTarget = (PDWORD)
					((DWORD)(pDllDos)
						+pReloc->VirtualAddress
						+ pTypeOffset->offset);
				// offset to .text: origAddr - dllbase - .text RVA
				dwTmp = *pdwTarget
					- (DWORD)pDllDos
					- (DWORD)(GetSectionHeader(pDllDos, lpFixSectionName)->VirtualAddress);

				// new offset to new section: exe base + new sectino RVA + dwTmp
				*pdwTarget = GetOptHeader32(pExeDos)->ImageBase
					+ (DWORD)(GetSectionHeader(pExeDos, lpStubSectionName)->VirtualAddress)
					+ dwTmp;
			}
		}

		VirtualProtect((LPVOID)(pReloc->VirtualAddress + (DWORD)pDllDos), 0x1000, dwOldProtect, NULL);


		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
	}

	/**************************
	*	v1.2
	*	support ASLR
	*******************************/
	//GetOptHeader32(pExeDos)->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	return 0;
}

PIMAGE_SECTION_HEADER MyPack::GetSectionHeader(PIMAGE_DOS_HEADER pDos, LPCSTR lpSectionName)
{
	PIMAGE_NT_HEADERS32 pNtHeader = GetNtHeader32(pDos);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	WORD wNumberSections = GetFileHeader(pDos)->NumberOfSections;
	for (WORD i = 0; i < wNumberSections; ++i)
	{
		if (!strcmp(lpSectionName, (const char*)pSectionHeader->Name))
		{
			return pSectionHeader;
		}
		++pSectionHeader;
	}

	return NULL;
}

int MyPack::SetOEP(LPCSTR lpStubSectionName, LPCSTR lpFuncName, LPCSTR lpFromSectionName/* = ".text"*/)
{
	DWORD dwStub = (DWORD)GetProcAddress((HMODULE)pDllDos, lpFuncName);
	DWORD dwStubOffset2Section = dwStub - (DWORD)pDllDos - (DWORD)(GetSectionHeader(pDllDos, lpFromSectionName)->VirtualAddress);

	pSharedData->dwOldOEP = GetOptHeader32(pExeDos)->AddressOfEntryPoint;

	GetNtHeader32(pExeDos)->OptionalHeader.AddressOfEntryPoint =
		GetSectionHeader(pExeDos, lpStubSectionName)->VirtualAddress
		+ dwStubOffset2Section;


	return 0;
}

/********************
*	1.0
********************/
int MyPack::EncryptText(LPCSTR lpSectionName/* = ".text"*/)
{
	srand(time(NULL));
	BYTE key = rand() % 0xFF;
	PIMAGE_SECTION_HEADER pSectionTarget = GetSectionHeader(pExeDos, lpSectionName);
	pSharedData->key = key;
	pSharedData->dwEncRVA = pSectionTarget->VirtualAddress;
	pSharedData->dwEncSize = pSectionTarget->SizeOfRawData;

	BYTE* pData = (BYTE*)((DWORD)pExeDos + pSectionTarget->PointerToRawData);
	for (DWORD i = 0; i < pSectionTarget->SizeOfRawData; ++i)
	{
		pData[i] = pData[i] ^ key;
	}

	return 0;
}

/********************
*	1.1
********************/
int MyPack::ClearIID()
{
	PIMAGE_DATA_DIRECTORY pDataDir = &(GetOptHeader32(pExeDos)->DataDirectory[1]);

	pSharedData->dwIIDRVA = pDataDir->VirtualAddress;
	pSharedData->dwIIDSize = pDataDir->Size;
	memset(pDataDir, 0, 8);

	pDataDir = &(GetOptHeader32(pExeDos)->DataDirectory[12]);
	memset(pDataDir, 0, 8);

	return 0;
}



/**********************
*	v1.2
*	Target exe should
*	repair the stub.
************************/
int MyPack::CopyStubReloc(LPCSTR lpStubSectionName, LPCSTR lpStubRelocName)
{
	// 1. Change DataDir[5].VirtualAddress to new stub .reloc copied.
	PIMAGE_SECTION_HEADER pLastSectionHeader = (PIMAGE_SECTION_HEADER)
		((ULONGLONG)IMAGE_FIRST_SECTION(GetNtHeader32(pExeDos))
			+ (GetFileHeader(pExeDos)->NumberOfSections - 1)
			* sizeof(IMAGE_SECTION_HEADER));

	// 1.1 store the original 8 bytes to sharedData.
	pSharedData->dwRelocRVA = GetOptHeader32(pExeDos)->DataDirectory[5].VirtualAddress;
	pSharedData->dwRelocSize = GetOptHeader32(pExeDos)->DataDirectory[5].Size;
	pSharedData->dwStubRVA = GetSectionHeader(pExeDos, lpStubSectionName)->VirtualAddress;
	pSharedData->dwTextRVA = GetSectionHeader(pExeDos, ".text")->VirtualAddress;
	pSharedData->dwTextSize = GetSectionHeader(pExeDos, ".text")->Misc.VirtualSize;
	pSharedData->dwDefImageBase = GetOptHeader32(pExeDos)->ImageBase;

	// 1.2 change DataDir[5]
	GetOptHeader32(pExeDos)->DataDirectory[5].VirtualAddress =
		pLastSectionHeader->VirtualAddress
		+ Alignment(pLastSectionHeader->Misc.VirtualSize, GetOptHeader32(pExeDos)->SectionAlignment);
	GetOptHeader32(pExeDos)->DataDirectory[5].Size =
		GetOptHeader32(pDllDos)->DataDirectory[5].Size;

	// 2. Copy stub .reloc to exe
	if (CopySectionHeader(lpStubRelocName, ".reloc") == -1) return -1;
	CopySectionBody(lpStubRelocName, ".reloc");
	return 0;
}

/****************************************************
*	v1.2
*	  After copying .rlc of stub.dll, the table
*	should be repaired.
******************************************************/
int MyPack::RepairStubReloc(LPCSTR lpStubSectionName, LPCSTR lpStubRelocName)
{
	DWORD dwStubRVA = GetSectionHeader(pExeDos, lpStubSectionName)->VirtualAddress;
	PIMAGE_BASE_RELOCATION pStubRlc = (PIMAGE_BASE_RELOCATION)
		((DWORD)pExeDos + GetSectionHeader(pExeDos, lpStubRelocName)->PointerToRawData);


	for (DWORD i = 0;
		pStubRlc->SizeOfBlock;
		++i)
	{
		pStubRlc->VirtualAddress = dwStubRVA + i * 0x1000;
		pStubRlc = (PIMAGE_BASE_RELOCATION)((DWORD)pStubRlc + pStubRlc->SizeOfBlock);
	}
	return 0;
}

int MyPack::GetPassword(LPCSTR lpPassword)
{
	memcpy(pSharedData->szPassword, lpPassword, 20);

	return 0;
}

int MyPack::CompressSection(LPCSTR lpSectionName)
{
	PIMAGE_SECTION_HEADER pTargetSectionHeader = GetSectionHeader(pExeDos, lpSectionName);

	// 1. Store shared data.
	pSharedData->dwCompressRVA = pTargetSectionHeader->VirtualAddress;
	pSharedData->dwCompressSizeBefore = pTargetSectionHeader->SizeOfRawData;

	char* pTarget = (char*)((DWORD)pExeDos + pTargetSectionHeader->PointerToRawData);


	// 2. compress
	int nEstimatedSize = LZ4_compressBound(pTargetSectionHeader->SizeOfRawData);
	char* pBuf = new char[nEstimatedSize]();
	pSharedData->dwCompressSizeAfter = LZ4_compress(
		pTarget,
		pBuf,
		pTargetSectionHeader->SizeOfRawData);
	memcpy(pTarget, pBuf, pSharedData->dwCompressSizeAfter);
	pTargetSectionHeader->SizeOfRawData = 
		Alignment(pSharedData->dwCompressSizeAfter,
			GetOptHeader32(pExeDos)->FileAlignment);

	// 3. Move secions below.
	PIMAGE_SECTION_HEADER pFrontSectionHeader = pTargetSectionHeader;
	PIMAGE_SECTION_HEADER pNextSectionHeader = pTargetSectionHeader + 1;
	while (pNextSectionHeader->VirtualAddress)
	{
		char* pDst = (char*)((DWORD)pExeDos + pFrontSectionHeader->PointerToRawData + pFrontSectionHeader->SizeOfRawData);
		char* pSrc = (char*)((DWORD)pExeDos + pNextSectionHeader->PointerToRawData);
		
		memcpy(pDst, pSrc, pNextSectionHeader->SizeOfRawData);

		pNextSectionHeader->PointerToRawData = pFrontSectionHeader->PointerToRawData + pFrontSectionHeader->SizeOfRawData;

		++pFrontSectionHeader;
		++pNextSectionHeader;
	}

	// 4. Don't modify SizeOfImage, static dwFileSize instead.
	dwFileSize = pFrontSectionHeader->PointerToRawData + pFrontSectionHeader->SizeOfRawData;

	// 5. realloc
	pExeDos = (PIMAGE_DOS_HEADER)realloc(pExeDos, dwFileSize);

	if (pBuf) delete(pBuf);

	return 0;
}

int MyPack::Pack(LPCSTR lpExePath, LPCSTR lpPassword)
{

	char szNewStubSectionName[] = ".foo";
	char szStubRelocName[] = ".foorlc";
	char szSaveFile[MAX_PATH] = { 0 };

	// 1. Read PE file
	if (MyPack::LoadFiles(lpExePath, "stub_15.dll") == -1)
	{
		MessageBoxA(NULL, "LoadPEFile() error", "ERROR", 0);
		MyPack::Release();
		return -1;
	}

	// 3. Copy section from stub
	MyPack::CopySectionHeader(szNewStubSectionName, ".text");

	// 4. Set OEP
	MyPack::SetOEP(szNewStubSectionName, "start");

	// 5. Fix reloc table
	MyPack::FixRelocTable(szNewStubSectionName);


	/***************** v1.5 added ************************/
	MyPack::CompressSection(".text");



	/*******************
	*	v1.1
	*	ProcessIID
	*********************/
	MyPack::ClearIID();

	/*************************************
	*	v1.2
	*	Copy and fix .reloc from DLL
	*  to EXE.
	**************************************/
	// 6. Copy section 
	MyPack::CopyStubReloc(szNewStubSectionName, szStubRelocName);
	MyPack::RepairStubReloc(szNewStubSectionName, szStubRelocName);

	/***************
	*	v1.0
	***************/
	MyPack::EncryptText();

	/**************************
	*	v1.3
	*	If argc == 3, argc[2] is
	*  the password
	*****************************/
	if (lpPassword)
	{
		MyPack::GetPassword(lpPassword);
	}


	MyPack::CopySectionBody(szNewStubSectionName, ".text");



	// 7. Save
	size_t nPathLen = strlen(lpExePath);
	memcpy_s(szSaveFile, MAX_PATH, lpExePath, nPathLen);
	memcpy_s(szSaveFile + nPathLen - 4, MAX_PATH + nPathLen - 4, "_packed.exe", 11);
	if (MyPack::SaveFile(szSaveFile) == -1)
	{
		MyPack::Release();
		return -1;
	}

	MyPack::Release();
	return 0;
}

int MyPack::SaveFile(LPCSTR lpPackedFileName)
{
	HANDLE hFile = CreateFileA(lpPackedFileName, GENERIC_WRITE, NULL, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	WriteFile(hFile, pExeDos, dwFileSize, NULL, NULL);

	CloseHandle(hFile);
	return 0;
}