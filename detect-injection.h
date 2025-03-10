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





#endif // DETECT