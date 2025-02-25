#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <tlhelp32.h>


HANDLE hProcessEnum() {
	return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

BOOL vProcessRetrieve(HANDLE funcProcEnum, PROCESSENTRY32* pe32) {
	if (!Process32First(funcProcEnum, pe32)) {
		_tprintf(_T("[!] Process32First error!\n"));
		return FALSE;
	}
	_tprintf(_T("[+] Retrieving process information ...\n"));
	Sleep(3000);
	do {
		_tprintf(_T("%25s %8d %8d %8d\n"),
			pe32->szExeFile,
			pe32->th32ProcessID,
			pe32->cntThreads,
			pe32->th32ParentProcessID
		);
	} while (Process32Next(funcProcEnum, pe32));
	return TRUE;
}

INT main(int argc, TCHAR *argv[]) {
	HANDLE funcProcEnum = hProcessEnum();
	if (funcProcEnum == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[!] CreateToolhelp32Snapshot error\n"));
		exit(EXIT_FAILURE);
	}
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!vProcessRetrieve(funcProcEnum, &pe32)) {
		_tprintf(_T("[!] Process retrieval failure\n"));
	}
	
	CloseHandle(funcProcEnum);  
	return 0;
}