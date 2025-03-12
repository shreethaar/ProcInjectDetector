#ifndef DETECT_INJECTION
#define DETECT_INJECTION

#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdbool.h>
#include <Shlwapi.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_PATH_LENGTH MAX_PATH
#define MAX_MODULE_COUNT 256
#define MAX_DETECTION_COUNT 1024


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
		// add detection-specific data here
	} data;
} DETECTION_INFO;

typedef void (*REPORT_CALLBACK)(const DETECTION_INFO* detection);

HANDLE EnumerateProcesses(void);
BOOL RetrieveProcess(HANDLE snapshot, REPORT_CALLBACK callback);
void CheckMemoryRegions(PROCESS_INFO* process_info, REPORT_CALLBACK callback);
void CheckLoadedModules(PROCESS_INFO* process_info, REPORT_CALLBACK callback);
BOOL GetProcessInfo(DWORD process_id, PROCESS_INFO* process_info);
BOOL GetMappedFileName(HANDLE process, LPVOID base_address, CHAR* file_path, SIZE_T path_size);



BOOL IsMemoryRegionSuspicious(MEMORY_REGION_INFO* region);
BOOL IsModuleSuspicious(MODULE_INFO* module_info);
BOOL IsFromTempFolder(const CHAR* file_path);
void ReportDetection(const DETECTION_INFO* detection);
void SaveDetectionsToFile(const CHAR* filename);


BOOL DetectRemoteThreads(PROCESS_INFO* process_info, REPORT_CALLBACK callback);
BOOL DetectHollowedProcesses(PROCESS_INFO* process_info, REPORT_CALLBACK callback);
BOOL DetectHiddenModules(PROCESS_INFO* process_info, REPORT_CALLBACK callback);
BOOL DetectAPIHooking(PROCESS_INFO* process_info, REPORT_CALLBACK callback);
BOOL CheckDigitalSignature(const CHAR* file_path);
BOOL AnalyzeMemoryContent(HANDLE process, LPVOID address, SIZE_T size, REPORT_CALLBACK callback);
DWORD CalculateMemoryEntropy(BYTE* buffer, SIZE_T size);


#endif // DETECT
