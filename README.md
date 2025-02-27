# ProcInjectDetector
A simple Windows-based tool to enumerate running processes and assist in detecting potential process injection techniques. Built as part of my exploration into malware analysis within Windows environments.

### Features:
- Enumerate ProcessUses: 
Windows API (Toolhelp API functions) to list all running processes.

- Scan Memory Region for code injection:
GetProcessImageFileNameA and VirtualQueryEx

- Check Memory Regions for executable and writeable permission
PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY


