#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <Psapi.h>

typedef struct {
    LPVOID base_address;
    SIZE_T region_size;
    DWORD protection;
} MEMORY_REGION_INFO;

typedef void (*REPORT_CALLBACK)(const char* process_name, MEMORY_REGION_INFO* region);

HANDLE hProcessEnum() {
    return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

void ReportSuspiciousMemory(const char* process_name, MEMORY_REGION_INFO* region) {
    printf("[!] Suspicious memory detected in process: %s\n", process_name);
    printf("    Base Address: %p\n", region->base_address);
    printf("    Region Size:  %llu bytes\n", (unsigned long long)region->region_size);
    printf("    Protection:   0x%X\n\n", region->protection);
}

void CheckMemoryRegions(DWORD process_id, REPORT_CALLBACK callback) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (!hProcess) return;

    MEMORY_BASIC_INFORMATION memInfo;
    LPBYTE address = NULL;
    char processName[MAX_PATH] = { 0 };

    if (GetProcessImageFileNameA(hProcess, processName, MAX_PATH) == 0) {
        strcpy_s(processName, sizeof(processName), "Unknown");
    }

    while (VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
        if (memInfo.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
            MEMORY_REGION_INFO region = {
                .base_address = memInfo.BaseAddress,
                .region_size = memInfo.RegionSize,
                .protection = memInfo.Protect
            };
            callback(processName, &region);
        }
        address += memInfo.RegionSize;
    }
    CloseHandle(hProcess);
}

BOOL vProcessRetrieve(HANDLE funcProcEnum) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(funcProcEnum, &pe32)) {
        _tprintf(_T("[!] Process32First error!\n"));
        return FALSE;
    }

    _tprintf(_T("[+] Retrieving process information ...\n"));
    Sleep(3000);

    do {
        _tprintf(_T("%25s %8d %8d %8d\n"),
            pe32.szExeFile,
            pe32.th32ProcessID,
            pe32.cntThreads,
            pe32.th32ParentProcessID);
        CheckMemoryRegions(pe32.th32ProcessID, ReportSuspiciousMemory);

    } while (Process32Next(funcProcEnum, &pe32));

    return TRUE;
}

INT main(int argc, TCHAR* argv[]) {
    HANDLE funcProcEnum = hProcessEnum();
    if (funcProcEnum == INVALID_HANDLE_VALUE) {
        _tprintf(_T("[!] CreateToolhelp32Snapshot error\n"));
        exit(EXIT_FAILURE);
    }

    if (!vProcessRetrieve(funcProcEnum)) {
        _tprintf(_T("[!] Process retrieval failure\n"));
    }

    CloseHandle(funcProcEnum);
    return 0;
}
