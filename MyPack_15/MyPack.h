#pragma once

/*********************************************
*	v1.5
*	Compress .text
************************************************/


#include <windows.h>

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

class MyPack
{
private:
	static DWORD dwFileSize;
	static PIMAGE_DOS_HEADER pExeDos;
	static PIMAGE_DOS_HEADER pDllDos;
	static PSHAREDDATA pSharedData;

private:
	static PIMAGE_NT_HEADERS32 GetNtHeader32(PIMAGE_DOS_HEADER pDos);
	static PIMAGE_FILE_HEADER GetFileHeader(PIMAGE_DOS_HEADER pDos);
	static PIMAGE_OPTIONAL_HEADER32 GetOptHeader32(PIMAGE_DOS_HEADER pDos);

	/********************
	*	Alignment
	*******************/
	static DWORD Alignment(DWORD dwSize, DWORD dwAlignment);

	/*********************
	* Get a section header
	**********************/
	static PIMAGE_SECTION_HEADER GetSectionHeader(PIMAGE_DOS_HEADER pDos, LPCSTR lpSectionName);

	/*********************
	* Read PE file
	*	v0.2 , Load dll besides EXE.
	**********************/
	static int LoadFiles(LPCSTR lpExeName, LPCSTR lpDllName);

	/*********************
	*	Release
	***********************/
	static int Release();

	/******************************
	*	v0.3 modified
	*		Copy a section header
	*	from DLL to EXE
	*******************************/
	static int CopySectionHeader(LPCSTR pNewSectionName, LPCSTR pFromSectionName);

	/***************************************
	*	v0.3 added
	*	Copy and fix a section
	* from DLL to EXE.
	****************************************/
	static int CopySectionBody(LPCSTR pNewSectionName, LPCSTR pFromSectionName);
	static int FixRelocTable(LPCSTR lpStubSectionName, LPCSTR lpFixSectionName = ".text");

	/*********************
	* Save
	**********************/
	static int SaveFile(LPCSTR lpPackedFileName);


	/*********************
	* Set OEP
	**********************/
	static int SetOEP(LPCSTR lpStubSectionName, LPCSTR lpFuncName, LPCSTR lpFromSectionName = ".text");

	/********************
	*	v1.0
	********************/
	static int EncryptText(LPCSTR lpSectionName = ".text");

	/*******************
	*	v1.1
	*	Clear IID at
	* DataDir[1]
	*********************/
	static int ClearIID();

	/************************************************
	*	v1.2
	* Support ASLR
	*
	*	CopyStubReloc():
	*		Copy stub .reloc to target exe.
	*	  After copying .rlc of stub.dll, the table
	*	should be repaired by RepairStubReloc().
	*************************************************/
	static int CopyStubReloc(LPCSTR lpStubSectionName, LPCSTR lpStubRelocName);
	static int RepairStubReloc(LPCSTR lpStubSectionName, LPCSTR lpStubRelocName);


	/*************************************
	*	v1.3 added
	*	Input Password
	***************************************/
	static int GetPassword(LPCSTR lpPassword);

	/*******************************
	*	v1.4
	*	Compress section
	********************************/
	static int CompressSection(LPCSTR lpSectionName);
public:

	// main method.
	static int Pack(LPCSTR lpExePath, LPCSTR lpPassword);
};
