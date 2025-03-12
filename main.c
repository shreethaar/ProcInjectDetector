#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <stdbool.h>
#include <shlwapi.h>    


#define MAX_PATH_LENGTH       MAX_PATH
#define MAX_MODULE_COUNT      256
#define MAX_DETECTION_COUNT   1024



typedef enum {
    SEVERITY_INFO = 0,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL
} SEVERITY_LEVEL;



typedef struct {
    LPVOID base_address;
    SIZE_T region_size;
    DWORD protection;
    CHAR mapped_file_path[MAX_PATH_LENGTH];
    BOOL is_private_memory;
    BOOL is_from_module;
} MEMORY_REGION_INFO;

typedef struct {
    HMODULE hModule;
    CHAR module_name[MAX_PATH_LENGTH];
    CHAR module_path[MAX_PATH_LENGTH];
    LPVOID base_address;
    SIZE_T image_size;
    BOOL is_from_temp_folder;
} MODULE_INFO;

typedef struct {
    DWORD process_id;
    CHAR process_name[MAX_PATH_LENGTH];
    CHAR process_path[MAX_PATH_LENGTH];
    DWORD parent_process_id;
    CHAR parent_process_name[MAX_PATH_LENGTH];
    DWORD thread_count;
} PROCESS_INFO;


typedef struct {
    DWORD process_id;
    CHAR process_name[MAX_PATH_LENGTH];
    CHAR detection_type[64];
    CHAR description[256];
    SEVERITY_LEVEL severity;
    union {
        MEMORY_REGION_INFO memory_region;
        MODULE_INFO module_info;
        // Other detection-specific data can be added here
    } data;
} DETECTION_INFO;


typedef void (*REPORT_CALLBACK)(const DETECTION_INFO* detection);
DETECTION_INFO g_detections[MAX_DETECTION_COUNT];
DWORD g_detection_count = 0;
HANDLE EnumerateProcesses(void);
BOOL RetrieveProcesses(HANDLE snapshot, REPORT_CALLBACK callback);
void CheckMemoryRegions(PROCESS_INFO* process_info, REPORT_CALLBACK callback);
void CheckLoadedModules(PROCESS_INFO* process_info, REPORT_CALLBACK callback);
BOOL GetProcessInfo(DWORD process_id, PROCESS_INFO* process_info);
BOOL GetMappedFileName(HANDLE process, LPVOID base_address, CHAR* file_path, SIZE_T path_size);
BOOL IsMemoryRegionSuspicious(MEMORY_REGION_INFO* region);
BOOL IsModuleSuspicious(MODULE_INFO* module_info);
BOOL IsFromTempFolder(const CHAR* file_path);
void ReportDetection(const DETECTION_INFO* detection);
void SaveDetectionsToFile(const CHAR* filename);


void ReportDetection(const DETECTION_INFO* detection) {
    if (g_detection_count < MAX_DETECTION_COUNT) {
        g_detections[g_detection_count++] = *detection;
    }
    printf("[!] %s in process: %s (PID: %lu)\n",
        detection->detection_type,
        detection->process_name,
        detection->process_id);
    printf("    Severity: ");
    switch (detection->severity) {
    case SEVERITY_INFO:    printf("Info\n");    break;
    case SEVERITY_LOW:     printf("Low\n");     break;
    case SEVERITY_MEDIUM:  printf("Medium\n");  break;
    case SEVERITY_HIGH:    printf("High\n");    break;
    case SEVERITY_CRITICAL:printf("Critical\n");break;
    default:               printf("Unknown\n"); break;
    }

    printf("    Description: %s\n", detection->description);



    if (strcmp(detection->detection_type, "Suspicious Memory") == 0) {
        printf("    Base Address: %p\n", detection->data.memory_region.base_address);
        printf("    Region Size:  %llu bytes\n", (unsigned long long)detection->data.memory_region.region_size);
        printf("    Protection:   0x%X\n", detection->data.memory_region.protection);
        if (detection->data.memory_region.mapped_file_path[0] != '\0') {
            printf("    Mapped File:  %s\n", detection->data.memory_region.mapped_file_path);
        }
    }
    else if (strcmp(detection->detection_type, "Suspicious Module") == 0) {
        printf("    Module Name:  %s\n", detection->data.module_info.module_name);
        printf("    Module Path:  %s\n", detection->data.module_info.module_path);
        printf("    Base Address: %p\n", detection->data.module_info.base_address);
        printf("    Image Size:   %llu bytes\n", (unsigned long long)detection->data.module_info.image_size);
    }

    printf("\n");
}

HANDLE EnumerateProcesses(void) {
    return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}
BOOL GetProcessInfo(DWORD process_id, PROCESS_INFO* process_info) {
    HANDLE hProcess;
    BOOL result = FALSE;


    ZeroMemory(process_info, sizeof(PROCESS_INFO));
    process_info->process_id = process_id;


    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (!hProcess) {
        return FALSE;
    }

    if (GetProcessImageFileNameA(hProcess, process_info->process_path, MAX_PATH_LENGTH) > 0) {
        char* process_name = strrchr(process_info->process_path, '\\');
        if (process_name) {
            strncpy_s(process_info->process_name, MAX_PATH_LENGTH, process_name + 1, MAX_PATH_LENGTH - 1);
        }
        else {
            strncpy_s(process_info->process_name, MAX_PATH_LENGTH, "Unknown", MAX_PATH_LENGTH - 1);
        }
        result = TRUE;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == process_id) {
                    process_info->parent_process_id = pe32.th32ParentProcessID;
                    process_info->thread_count = pe32.cntThreads;
                    HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        FALSE, pe32.th32ParentProcessID);
                    if (hParentProcess) {
                        if (GetProcessImageFileNameA(hParentProcess, process_info->parent_process_name,
                            MAX_PATH_LENGTH) > 0) {
                            char* parent_name = strrchr(process_info->parent_process_name, '\\');
                            if (parent_name) {
                                memmove(process_info->parent_process_name, parent_name + 1,
                                    strlen(parent_name + 1) + 1);
                            }
                        }
                        CloseHandle(hParentProcess);
                    }
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    CloseHandle(hProcess);
    return result;
}

BOOL IsMemoryRegionSuspicious(MEMORY_REGION_INFO* region) {
    if (region->protection & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        return TRUE;
    }
    if (region->is_private_memory &&
        (region->protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ))) {
        return TRUE;
    }

    return FALSE;
}

BOOL IsModuleSuspicious(MODULE_INFO* module_info) {

    if (module_info->is_from_temp_folder) {
        return TRUE;
    }



    return FALSE;
}

BOOL IsFromTempFolder(const CHAR* file_path) {
    CHAR temp_path[MAX_PATH_LENGTH];

    if (GetTempPathA(MAX_PATH_LENGTH, temp_path) == 0) {
        return FALSE;
    }

    CHAR lower_file_path[MAX_PATH_LENGTH];
    CHAR lower_temp_path[MAX_PATH_LENGTH];

    strncpy_s(lower_file_path, MAX_PATH_LENGTH, file_path, MAX_PATH_LENGTH - 1);
    strncpy_s(lower_temp_path, MAX_PATH_LENGTH, temp_path, MAX_PATH_LENGTH - 1);

    _strlwr_s(lower_file_path, MAX_PATH_LENGTH);
    _strlwr_s(lower_temp_path, MAX_PATH_LENGTH);
    return (strstr(lower_file_path, lower_temp_path) != NULL);
}
BOOL GetMappedFileName(HANDLE process, LPVOID base_address, CHAR* file_path, SIZE_T path_size) {
    DWORD result = GetMappedFileNameA(process, base_address, file_path, (DWORD)path_size);
    if (result == 0) {
        file_path[0] = '\0';
        return FALSE;
    }
    CHAR drive_strings[512];
    CHAR drive[3] = " :";
    CHAR device_name[MAX_PATH_LENGTH];
    CHAR* p = file_path;

    if (!GetLogicalDriveStringsA(sizeof(drive_strings) - 1, drive_strings)) {
        return TRUE;  
    }

    CHAR* drive_ptr = drive_strings;
    while (*drive_ptr) {
        drive[0] = *drive_ptr;

        if (QueryDosDeviceA(drive, device_name, MAX_PATH_LENGTH)) {
            SIZE_T device_name_len = strlen(device_name);

            if (strncmp(file_path, device_name, device_name_len) == 0) {
                CHAR temp_path[MAX_PATH_LENGTH];
                sprintf_s(temp_path, MAX_PATH_LENGTH, "%s%s", drive, file_path + device_name_len);
                strncpy_s(file_path, path_size, temp_path, path_size - 1);
                return TRUE;
            }
        }
        while (*drive_ptr++);
    }

    return TRUE;
}

void CheckMemoryRegions(PROCESS_INFO* process_info, REPORT_CALLBACK callback) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_info->process_id);
    if (!hProcess) {
        return;
    }

    MEMORY_BASIC_INFORMATION memInfo;
    LPBYTE address = NULL;

    while (VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
        if (memInfo.State == MEM_COMMIT) {
            MEMORY_REGION_INFO region = { 0 };
            region.base_address = memInfo.BaseAddress;
            region.region_size = memInfo.RegionSize;
            region.protection = memInfo.Protect;
            region.is_private_memory = (memInfo.Type == MEM_PRIVATE);

            GetMappedFileName(hProcess, memInfo.BaseAddress, region.mapped_file_path, MAX_PATH_LENGTH);
            region.is_from_module = (region.mapped_file_path[0] != '\0');
            if (IsMemoryRegionSuspicious(&region)) {
                DETECTION_INFO detection = { 0 };
                detection.process_id = process_info->process_id;
                strncpy_s(detection.process_name, MAX_PATH_LENGTH, process_info->process_name, MAX_PATH_LENGTH - 1);
                strncpy_s(detection.detection_type, sizeof(detection.detection_type), "Suspicious Memory", sizeof(detection.detection_type) - 1);
                if (region.protection & PAGE_EXECUTE_READWRITE) {
                    strncpy_s(detection.description, sizeof(detection.description),
                        "Memory region with READ+WRITE+EXECUTE permissions (RWX)",
                        sizeof(detection.description) - 1);
                    detection.severity = SEVERITY_HIGH;
                }
                else if (region.protection & PAGE_EXECUTE_WRITECOPY) {
                    strncpy_s(detection.description, sizeof(detection.description),
                        "Memory region with EXECUTE+WRITECOPY permissions",
                        sizeof(detection.description) - 1);
                    detection.severity = SEVERITY_MEDIUM;
                }
                else if (region.is_private_memory && (region.protection & PAGE_EXECUTE)) {
                    strncpy_s(detection.description, sizeof(detection.description),
                        "Private memory with EXECUTE permissions",
                        sizeof(detection.description) - 1);
                    detection.severity = SEVERITY_MEDIUM;
                }

                detection.data.memory_region = region;

    

                callback(&detection);
            }
        }
        if ((SIZE_T)address + memInfo.RegionSize < (SIZE_T)address) {
                 break;
        }

        address += memInfo.RegionSize;
    }

    CloseHandle(hProcess);
}

void CheckLoadedModules(PROCESS_INFO* process_info, REPORT_CALLBACK callback) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_info->process_id);
    if (!hProcess) {
        return;
    }
    HMODULE hModules[MAX_MODULE_COUNT];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        DWORD module_count = cbNeeded / sizeof(HMODULE);

        for (DWORD i = 0; i < module_count && i < MAX_MODULE_COUNT; i++) {
            MODULE_INFO module_info = { 0 };
            module_info.hModule = hModules[i];
            module_info.base_address = hModules[i];

            if (GetModuleFileNameExA(hProcess, hModules[i], module_info.module_path, MAX_PATH_LENGTH) == 0) {
                continue;
            }
            char* module_name = strrchr(module_info.module_path, '\\');
            if (module_name) {
                strncpy_s(module_info.module_name, MAX_PATH_LENGTH, module_name + 1, MAX_PATH_LENGTH - 1);
            }
            else {
                strncpy_s(module_info.module_name, MAX_PATH_LENGTH, module_info.module_path, MAX_PATH_LENGTH - 1);
            }

            MODULEINFO mi;
            if (GetModuleInformation(hProcess, hModules[i], &mi, sizeof(mi))) {
                module_info.image_size = mi.SizeOfImage;
            }

            module_info.is_from_temp_folder = IsFromTempFolder(module_info.module_path);
            if (IsModuleSuspicious(&module_info)) {
                DETECTION_INFO detection = { 0 };
                detection.process_id = process_info->process_id;
                strncpy_s(detection.process_name, MAX_PATH_LENGTH, process_info->process_name, MAX_PATH_LENGTH - 1);
                strncpy_s(detection.detection_type, sizeof(detection.detection_type), "Suspicious Module", sizeof(detection.detection_type) - 1);

                if (module_info.is_from_temp_folder) {
                    strncpy_s(detection.description, sizeof(detection.description),
                        "Module loaded from temporary directory",
                        sizeof(detection.description) - 1);
                    detection.severity = SEVERITY_HIGH;
                }

                detection.data.module_info = module_info;
                callback(&detection);
            }
        }
    }

    CloseHandle(hProcess);
}

void SaveDetectionsToFile(const CHAR* filename) {
    FILE* file;
    errno_t err = fopen_s(&file, filename, "w");

    if (err != 0 || !file) {
        printf("[!] Error: Could not open file for writing: %s\n", filename);
        return;
    }

    fprintf(file, "Process Injection Detection Report\n");
    fprintf(file, "================================\n\n");
    fprintf(file, "Total Detections: %lu\n\n", g_detection_count);

    for (DWORD i = 0; i < g_detection_count; i++) {
        const DETECTION_INFO* detection = &g_detections[i];

        fprintf(file, "Detection #%lu\n", i + 1);
        fprintf(file, "  Process:     %s (PID: %lu)\n", detection->process_name, detection->process_id);
        fprintf(file, "  Type:        %s\n", detection->detection_type);
        fprintf(file, "  Severity:    ");

        switch (detection->severity) {
        case SEVERITY_INFO:    fprintf(file, "Info\n");    break;
        case SEVERITY_LOW:     fprintf(file, "Low\n");     break;
        case SEVERITY_MEDIUM:  fprintf(file, "Medium\n");  break;
        case SEVERITY_HIGH:    fprintf(file, "High\n");    break;
        case SEVERITY_CRITICAL:fprintf(file, "Critical\n");break;
        default:               fprintf(file, "Unknown\n"); break;
        }

        fprintf(file, "  Description: %s\n", detection->description);

        if (strcmp(detection->detection_type, "Suspicious Memory") == 0) {
            fprintf(file, "  Base Address: %p\n", detection->data.memory_region.base_address);
            fprintf(file, "  Region Size:  %llu bytes\n", (unsigned long long)detection->data.memory_region.region_size);
            fprintf(file, "  Protection:   0x%X\n", detection->data.memory_region.protection);

            if (detection->data.memory_region.mapped_file_path[0] != '\0') {
                fprintf(file, "  Mapped File:  %s\n", detection->data.memory_region.mapped_file_path);
            }
        }
        else if (strcmp(detection->detection_type, "Suspicious Module") == 0) {
            fprintf(file, "  Module Name:  %s\n", detection->data.module_info.module_name);
            fprintf(file, "  Module Path:  %s\n", detection->data.module_info.module_path);
            fprintf(file, "  Base Address: %p\n", detection->data.module_info.base_address);
            fprintf(file, "  Image Size:   %llu bytes\n", (unsigned long long)detection->data.module_info.image_size);
        }

        fprintf(file, "\n");
    }

    fclose(file);
    printf("[+] Detection report saved to: %s\n", filename);
}

BOOL RetrieveProcesses(HANDLE snapshot, REPORT_CALLBACK callback) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe32)) {
        _tprintf(_T("[!] Process32First error: %d\n"), GetLastError());
        return FALSE;
    }

    _tprintf(_T("[+] Retrieving process information...\n"));
    _tprintf(_T("%-25s %-8s %-8s %-8s\n"), _T("Process Name"), _T("PID"), _T("Threads"), _T("Parent PID"));
    _tprintf(_T("----------------------------------------------------------------\n"));

    do {
        _tprintf(_T("%-25s %-8d %-8d %-8d\n"),
            pe32.szExeFile,
            pe32.th32ProcessID,
            pe32.cntThreads,
            pe32.th32ParentProcessID);

        PROCESS_INFO process_info = { 0 };
        if (GetProcessInfo(pe32.th32ProcessID, &process_info)) {
            CheckMemoryRegions(&process_info, callback);
            CheckLoadedModules(&process_info, callback);
        }

    } while (Process32Next(snapshot, &pe32));

    return TRUE;
}

INT main(int argc, TCHAR* argv[]) {
    printf("Process Injection Detector\n");
    printf("=========================\n\n");
    HANDLE snapshot = EnumerateProcesses();
    if (snapshot == INVALID_HANDLE_VALUE) {
        _tprintf(_T("[!] CreateToolhelp32Snapshot error: %d\n"), GetLastError());
        exit(EXIT_FAILURE);
    }
    g_detection_count = 0;
    if (!RetrieveProcesses(snapshot, ReportDetection)) {
        _tprintf(_T("[!] Process retrieval failure\n"));
    }
    CloseHandle(snapshot);
    printf("\n[+] Scan complete.\n");
    printf("[+] Total detections: %lu\n", g_detection_count);

    if (g_detection_count > 0) {
        SaveDetectionsToFile("injection_detections.txt");
    }

    return EXIT_SUCCESS;
}
