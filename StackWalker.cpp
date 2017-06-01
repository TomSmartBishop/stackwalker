/**********************************************************************
 *
 *   StackWalker.cpp
 *   http://stackwalker.codeplex.com/
 *
 *   LICENSE (http://www.opensource.org/licenses/bsd-license.php)
 *
 *   Copyright (c) 2005-2013, Jochen Kalmbach
 *   All rights reserved.
 *
 **********************************************************************/
#include "pch/pch.hpp"


struct StackWalker::Internal {

    typedef BOOL (__stdcall *tSymCleanup) (IN HANDLE hProcess);
    tSymCleanup pSymCleanup;

    typedef PVOID (__stdcall *tSymFunctionTableAccess64) (HANDLE hProcess, DWORD64 AddrBase);
    tSymFunctionTableAccess64 pSymFunctionTableAccess64;

    typedef BOOL (__stdcall *tSymGetLineFromAddr64) (IN HANDLE hProcess,
                                                     IN DWORD64 dwAddr,
                                                     OUT PDWORD pdwDisplacement,
                                                     OUT PIMAGEHLP_LINE64 Line);
    tSymGetLineFromAddr64 pSymGetLineFromAddr64;

    typedef DWORD64 (__stdcall *tSymGetModuleBase64) (IN HANDLE hProcess, IN DWORD64 dwAddr);
    tSymGetModuleBase64 pSymGetModuleBase64;

    typedef BOOL (__stdcall *tSymGetModuleInfo64) (IN HANDLE hProcess,
                                                   IN DWORD64 dwAddr,
                                                   OUT IMAGEHLP_MODULE64_V3 *ModuleInfo);
    tSymGetModuleInfo64 pSymGetModuleInfo64;

    typedef DWORD (__stdcall *tSymGetOptions) (VOID);
    tSymGetOptions pSymGetOptions;

    typedef BOOL (__stdcall *tSymGetSymFromAddr64) (IN HANDLE hProcess,
                                                    IN DWORD64 dwAddr,
                                                    OUT PDWORD64 pdwDisplacement,
                                                    OUT PIMAGEHLP_SYMBOL64 Symbol);
    tSymGetSymFromAddr64 pSymGetSymFromAddr64;

    typedef BOOL (__stdcall *tSymInitialize) (IN HANDLE hProcess, IN PSTR UserSearchPath, IN BOOL fInvadeProcess);
    tSymInitialize pSymInitialize;

    typedef DWORD64 (__stdcall *tSymLoadModule64) (IN HANDLE hProcess,
                                                   IN HANDLE hFile,
                                                   IN PSTR ImageName,
                                                   IN PSTR ModuleName,
                                                   IN DWORD64 BaseOfDll,
                                                   IN DWORD SizeOfDll);
    tSymLoadModule64 pSymLoadModule64;

    typedef DWORD (__stdcall *tSymSetOptions) (IN DWORD SymOptions);
    tSymSetOptions pSymSetOptions;

    typedef BOOL (__stdcall *tStackWalk64) (DWORD MachineType,
                                            HANDLE hProcess,
                                            HANDLE hThread,
                                            LPSTACKFRAME64 StackFrame,
                                            PVOID ContextRecord,
                                            PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
                                            PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                                            PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
                                            PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
    tStackWalk64 pStackWalk64;

    typedef DWORD (__stdcall WINAPI *tUnDecorateSymbolName) (PCSTR DecoratedName,
                                                             PSTR UnDecoratedName,
                                                             DWORD UndecoratedLength,
                                                             DWORD Flags);
    tUnDecorateSymbolName pUnDecorateSymbolName;

    BOOL GetModuleListTH32 (StackWalker *parent, HANDLE hProcess, DWORD pid) {

        typedef HANDLE (__stdcall * tCreateToolhelp32Snapshot) (DWORD dwFlags, DWORD th32ProcessID);
        typedef BOOL (__stdcall * tModule32First) (HANDLE hSnapshot, LPMODULEENTRY32 lpme);
        typedef BOOL (__stdcall * tModule32Next) (HANDLE hSnapshot, LPMODULEENTRY32 lpme);

        // try both dlls...
        const TCHAR *dllname[] = { _T("kernel32.dll"), _T("tlhelp32.dll") };
        HINSTANCE hToolhelp = NULL;
        tCreateToolhelp32Snapshot pCreateToolhelp32Snapshot = NULL;
        tModule32First pModule32First = NULL;
        tModule32Next pModule32Next = NULL;

        HANDLE hSnapshot;
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof (moduleEntry);

        for (size_t i = 0; i < (sizeof (dllname) / sizeof (dllname[0])); i++) {
            hToolhelp = LoadLibrary (dllname[i]);
            if (hToolhelp == NULL)
                continue;
            pCreateToolhelp32Snapshot =
            (tCreateToolhelp32Snapshot)GetProcAddress (hToolhelp, "CreateToolhelp32Snapshot");
            pModule32First = (tModule32First)GetProcAddress (hToolhelp, "Module32First");
            pModule32Next = (tModule32Next)GetProcAddress (hToolhelp, "Module32Next");
            if ((pCreateToolhelp32Snapshot != NULL) && (pModule32First != NULL) && (pModule32Next != NULL))
                break; // found the functions!
            FreeLibrary (hToolhelp);
            hToolhelp = NULL;
        }

        if (hToolhelp == NULL)
            return FALSE;

        hSnapshot = pCreateToolhelp32Snapshot (TH32CS_SNAPMODULE, pid);
        if (hSnapshot == (HANDLE)-1) {
            FreeLibrary (hToolhelp);
            return FALSE;
        }

        BOOL keepGoing = !!pModule32First (hSnapshot, &moduleEntry);
        int cnt = 0;
        while (keepGoing) {
            LoadModule (parent, hProcess, moduleEntry.szExePath, moduleEntry.szModule,
                        (DWORD64)moduleEntry.modBaseAddr, moduleEntry.modBaseSize);
            cnt++;
            keepGoing = !!pModule32Next (hSnapshot, &moduleEntry);
        }
        CloseHandle (hSnapshot);
        FreeLibrary (hToolhelp);
        if (cnt <= 0)
            return FALSE;
        return TRUE;
    } // GetModuleListTH32

    // **************************************** PSAPI ************************
    typedef struct _MODULEINFO {
        LPVOID lpBaseOfDll;
        DWORD SizeOfImage;
        LPVOID EntryPoint;
    } MODULEINFO, *LPMODULEINFO;

    BOOL GetModuleListPSAPI (StackWalker *parent, HANDLE hProcess) {

        typedef BOOL (__stdcall * tEnumProcessModules) (HANDLE hProcess, HMODULE * lphModule,
                                                        DWORD cb, LPDWORD lpcbNeeded);
        typedef DWORD (__stdcall * tGetModuleFileNameEx) (HANDLE hProcess, HMODULE hModule,
                                                          LPSTR lpFilename, DWORD nSize);
        typedef DWORD (__stdcall * tGetModuleBaseName) (HANDLE hProcess, HMODULE hModule,
                                                        LPSTR lpFilename, DWORD nSize);
        typedef BOOL (__stdcall * tGetModuleInformation) (HANDLE hProcess, HMODULE hModule,
                                                          LPMODULEINFO pmi, DWORD nSize);

        HINSTANCE hPsapi = LoadLibrary (_T("psapi.dll"));
        if (hPsapi == NULL)
            return FALSE;

        tEnumProcessModules pEnumProcessModules;
        tGetModuleFileNameEx pGetModuleFileNameExA;
        tGetModuleBaseName pGetModuleBaseNameA;
        tGetModuleInformation pGetModuleInformation;

        DWORD cbNeeded;
        HMODULE hMods[sizeof (HMODULE) * (Parameter::STACKWALKER_MAX_TEMP_BUFFER / sizeof (HMODULE))];

        pEnumProcessModules = (tEnumProcessModules)GetProcAddress (hPsapi, "EnumProcessModules");
        pGetModuleFileNameExA =
        (tGetModuleFileNameEx)GetProcAddress (hPsapi, "GetModuleFileNameExA");
        pGetModuleBaseNameA = (tGetModuleFileNameEx)GetProcAddress (hPsapi, "GetModuleBaseNameA");
        pGetModuleInformation =
        (tGetModuleInformation)GetProcAddress (hPsapi, "GetModuleInformation");

        if ((pEnumProcessModules == NULL) || (pGetModuleFileNameExA == NULL) ||
            (pGetModuleBaseNameA == NULL) || (pGetModuleInformation == NULL) ||
            !pEnumProcessModules (hProcess, hMods, Parameter::STACKWALKER_MAX_TEMP_BUFFER, &cbNeeded) ||
            cbNeeded > Parameter::STACKWALKER_MAX_TEMP_BUFFER) {
            // we couldn't find all functions
            FreeLibrary (hPsapi);
            return FALSE;
        }

        char imageFileName[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
        char moduleFileName[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
        int count = 0;
        MODULEINFO moduleInfo;

        for (DWORD i = 0; i < cbNeeded / sizeof hMods[0]; i++) {
            // base address, size
            pGetModuleInformation (hProcess, hMods[i], &moduleInfo, sizeof moduleInfo);
            // image file name
            imageFileName[0] = 0;
            pGetModuleFileNameExA (hProcess, hMods[i], imageFileName, Parameter::STACKWALKER_MAX_TEMP_BUFFER);
            // module name
            moduleFileName[0] = 0;
            pGetModuleBaseNameA (hProcess, hMods[i], moduleFileName, Parameter::STACKWALKER_MAX_TEMP_BUFFER);

            DWORD dwRes = LoadModule (parent, hProcess, imageFileName, moduleFileName,
                                      (DWORD64)moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);
            if (dwRes != ERROR_SUCCESS)
                parent->OnDbgHelpErr ("LoadModule", dwRes, 0);
            count++;
        }

        return count != 0;
    } // GetModuleListPSAPI

    DWORD LoadModule (StackWalker *parent, HANDLE hProcess, LPCSTR img, LPCSTR mod, DWORD64 baseAddr, DWORD size) {
        CHAR szImg[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
        CHAR szMod[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
        SW_ASSERT (strlen (img) < Parameter::STACKWALKER_MAX_TEMP_BUFFER,
                   "Image name buffer size not sufficient");
        memcpy (szImg, img, strlen (img) + 1);
        SW_ASSERT (strlen (img) < Parameter::STACKWALKER_MAX_TEMP_BUFFER,
                   "Module name buffer size not sufficient");
        memcpy (szMod, mod, strlen (mod) + 1);

        DWORD result = ERROR_SUCCESS;
        if (pSymLoadModule64 (hProcess, 0, szImg, szMod, baseAddr, size) == 0) {
            return GetLastError ();
        }

        ULONGLONG fileVersion = 0;
        if ((parent != NULL) && (szImg != NULL)) {
            // try to retrieve the file-version:
            if ((parent->m_options & StackWalker::RetrieveFileVersion) != 0) {
                VS_FIXEDFILEINFO *fInfo = NULL;
                DWORD dwHandle;
                DWORD dwSize = GetFileVersionInfoSizeA (szImg, &dwHandle);
                if (dwSize > 0) {
                    LPVOID vData = malloc (dwSize);
                    if (vData != NULL) {
                        if (GetFileVersionInfoA (szImg, dwHandle, dwSize, vData) != 0) {
                            UINT len;
                            TCHAR szSubBlock[] = _T("\\");
                            if (VerQueryValue (vData, szSubBlock, (LPVOID *)&fInfo, &len) == 0)
                                fInfo = NULL;
                            else {
                                fileVersion = ((ULONGLONG)fInfo->dwFileVersionLS) +
                                              ((ULONGLONG)fInfo->dwFileVersionMS << 32);
                            }
                        }
                        free (vData);
                    }
                }
            }

            if ((parent->m_options & StackWalker::RetrieveModuleInfo) != 0) {
                // Retrieve some additional-infos about the module
                IMAGEHLP_MODULE64_V3 Module;
                const char *szSymType = "-unknown-";
                if (GetModuleInfo (hProcess, baseAddr, &Module) != FALSE) {
                    switch (Module.SymType) {
                        case SymNone:
                            szSymType = "-nosymbols-";
                            break;
                        case SymCoff: // 1
                            szSymType = "COFF";
                            break;
                        case SymCv: // 2
                            szSymType = "CV";
                            break;
                        case SymPdb: // 3
                            szSymType = "PDB";
                            break;
                        case SymExport: // 4
                            szSymType = "-exported-";
                            break;
                        case SymDeferred: // 5
                            szSymType = "-deferred-";
                            break;
                        case SymSym: // 6
                            szSymType = "SYM";
                            break;
                        case 7: // SymDia:
                            szSymType = "DIA";
                            break;
                        case 8: // SymVirtual:
                            szSymType = "Virtual";
                            break;
                    }
                }
                LPCSTR pdbName = Module.LoadedImageName;
                if (Module.LoadedPdbName[0] != 0)
                    pdbName = Module.LoadedPdbName;
                parent->OnLoadModule (img, mod, baseAddr, size, result, szSymType, pdbName, fileVersion);
            }
        }

        return result;
    }

    static const wchar_t *Internal::dbg_help_path[];

    void DeInit (StackWalker *parent) {
        if (pSymCleanup != NULL)
            pSymCleanup (m_hProcess); // SymCleanup
        if (m_hDbhHelp != NULL)
            FreeLibrary (m_hDbhHelp);
        m_hDbhHelp = NULL;
        parent = NULL;
    }

    BOOL Init (StackWalker *parent, HANDLE hProcess, LPCSTR szSymPath) {

        static_assert (sizeof (Internal) < Parameter::STACKWALKER_INTERNAL_STRUCT_SIZE, "Increase buffer size");

        if (parent == NULL)
            return FALSE;

        m_hDbhHelp = NULL;
        pSymCleanup = NULL;
        m_hProcess = hProcess;
        m_szSymPath[0] = 0;
        pSymFunctionTableAccess64 = NULL;
        pSymGetLineFromAddr64 = NULL;
        pSymGetModuleBase64 = NULL;
        pSymGetModuleInfo64 = NULL;
        pSymGetOptions = NULL;
        pSymGetSymFromAddr64 = NULL;
        pSymInitialize = NULL;
        pSymLoadModule64 = NULL;
        pSymSetOptions = NULL;
        pStackWalk64 = NULL;
        pUnDecorateSymbolName = NULL;

        // Dynamically load the Entry-Points for dbghelp.dll:
        // First try to load the newest one from
        TCHAR szTemp[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
        // But before we do this, we first check if the ".local" file exists
        if (GetModuleFileName (NULL, szTemp, Parameter::STACKWALKER_MAX_TEMP_BUFFER) > 0) {
            _tcscat_s (szTemp, _T(".local"));
            if (GetFileAttributes (szTemp) == INVALID_FILE_ATTRIBUTES) {
                // ".local" file does not exist, so we can try to load the dbghelp.dll from the
                // "Debugging Tools for Windows" Ok, first try the new path according to the
                // architecture:
                DWORD result = GetEnvironmentVariable (_T("ProgramFiles"), szTemp,
                                                       Parameter::STACKWALKER_MAX_TEMP_BUFFER);
                int idx = 0;
                while (result > 0 && dbg_help_path[idx][0] != 0) {
                    _tcscat_s (szTemp, dbg_help_path[idx]);
                    // now check if the file exists:
                    if (GetFileAttributes (szTemp) != INVALID_FILE_ATTRIBUTES) {
                        m_hDbhHelp = LoadLibrary (szTemp);
                        break;
                    }
                    idx++;
                }
            }
        }
        if (m_hDbhHelp == NULL) // if not already loaded, try to load a default-one
            m_hDbhHelp = LoadLibrary (_T("dbghelp.dll"));
        if (m_hDbhHelp == NULL)
            return FALSE;
        pSymInitialize = (tSymInitialize)GetProcAddress (m_hDbhHelp, "SymInitialize");
        pSymCleanup = (tSymCleanup)GetProcAddress (m_hDbhHelp, "SymCleanup");

        pStackWalk64 = (tStackWalk64)GetProcAddress (m_hDbhHelp, "StackWalk64");
        pSymGetOptions = (tSymGetOptions)GetProcAddress (m_hDbhHelp, "SymGetOptions");
        pSymSetOptions = (tSymSetOptions)GetProcAddress (m_hDbhHelp, "SymSetOptions");

        pSymFunctionTableAccess64 =
        (tSymFunctionTableAccess64)GetProcAddress (m_hDbhHelp, "SymFunctionTableAccess64");
        pSymGetLineFromAddr64 =
        (tSymGetLineFromAddr64)GetProcAddress (m_hDbhHelp, "SymGetLineFromAddr64");
        pSymGetModuleBase64 =
        (tSymGetModuleBase64)GetProcAddress (m_hDbhHelp, "SymGetModuleBase64");
        pSymGetModuleInfo64 =
        (tSymGetModuleInfo64)GetProcAddress (m_hDbhHelp, "SymGetModuleInfo64");
        pSymGetSymFromAddr64 =
        (tSymGetSymFromAddr64)GetProcAddress (m_hDbhHelp, "SymGetSymFromAddr64");
        pUnDecorateSymbolName =
        (tUnDecorateSymbolName)GetProcAddress (m_hDbhHelp, "UnDecorateSymbolName");
        pSymLoadModule64 = (tSymLoadModule64)GetProcAddress (m_hDbhHelp, "SymLoadModule64");
        

        if (pSymCleanup == NULL || pSymFunctionTableAccess64 == NULL ||
            pSymGetModuleBase64 == NULL || pSymGetModuleInfo64 == NULL || pSymGetOptions == NULL ||
            pSymGetSymFromAddr64 == NULL || pSymInitialize == NULL || pSymSetOptions == NULL ||
            pStackWalk64 == NULL || pUnDecorateSymbolName == NULL || pSymLoadModule64 == NULL) {
            FreeLibrary (m_hDbhHelp);
            m_hDbhHelp = NULL;
            pSymCleanup = NULL;
            return FALSE;
        }

        // SymInitialize
        if (szSymPath != NULL && szSymPath[0] != 0)
            strcpy_s (m_szSymPath, strlen (szSymPath) + 1, szSymPath);
        if (pSymInitialize (m_hProcess, m_szSymPath, FALSE) == FALSE)
            parent->OnDbgHelpErr ("SymInitialize", GetLastError (), 0);

        DWORD symOptions = pSymGetOptions();
		if (parent->m_options & RetrieveLineAndFile)
		{
			symOptions |= SYMOPT_LOAD_LINES;
		}
        symOptions |= SYMOPT_FAIL_CRITICAL_ERRORS; //Do not display system dialog boxes when there is a media failure 
        // symOptions |= SYMOPT_NO_PROMPTS; //Prevents prompting for validation from the symbol server.

        symOptions = pSymSetOptions (symOptions);

        
        if (parent->m_options & StackWalker::RetrieveSymbolInfo) {

			char searchPath[Parameter::STACKWALKER_MAX_NAMELEN] = { 0 };
			typedef BOOL(__stdcall WINAPI *tSymGetSearchPath) (HANDLE hProcess, PSTR SearchPath, DWORD SearchPathLength);
			tSymGetSearchPath pSymGetSearchPath = (tSymGetSearchPath)GetProcAddress(m_hDbhHelp, "SymGetSearchPath");

			if (pSymGetSearchPath != NULL) {
				if (pSymGetSearchPath(m_hProcess, searchPath, Parameter::STACKWALKER_MAX_NAMELEN) == FALSE)
					parent->OnDbgHelpErr("SymGetSearchPath", GetLastError(), 0);
			}

            parent->OnSymbolInfo(searchPath, symOptions);
        }
        return TRUE;
    }
    BOOL LoadModules (StackWalker *parent, HANDLE hProcess, DWORD dwProcessId) {
        if (GetModuleListTH32 (parent, hProcess, dwProcessId))
            return true;
        // try psapi as backup
        return GetModuleListPSAPI (parent, hProcess);
    }

    BOOL GetModuleInfo (HANDLE hProcess, DWORD64 baseAddr, IMAGEHLP_MODULE64_V3 *pModuleInfo) {
        memset (pModuleInfo, 0, sizeof (IMAGEHLP_MODULE64_V3));
        if (pSymGetModuleInfo64 == NULL) {
            SetLastError (ERROR_DLL_INIT_FAILED);
            return FALSE;
        }
        // First try to use the larger ModuleInfo-Structure
        pModuleInfo->SizeOfStruct = sizeof (IMAGEHLP_MODULE64_V3);
        char pData[sizeof (IMAGEHLP_MODULE64_V3) * 2]; // reserve enough memory, so the bug in
                                                       // v6.3.5.1 does not lead to
                                                       // memory-overwrites...

        memcpy (pData, pModuleInfo, sizeof (IMAGEHLP_MODULE64_V3));
        static bool s_useV3Version = true;
        if (s_useV3Version) {
            if (pSymGetModuleInfo64 (hProcess, baseAddr, (IMAGEHLP_MODULE64_V3 *)pData) != FALSE) {
                // only copy as much memory as is reserved...
                memcpy (pModuleInfo, pData, sizeof (IMAGEHLP_MODULE64_V3));
                pModuleInfo->SizeOfStruct = sizeof (IMAGEHLP_MODULE64_V3);
                return TRUE;
            }
            s_useV3Version = false; // to prevent unnecessary calls with the larger struct...
        }

        // could not retrieve the bigger structure, try with the smaller one (as
        // defined in VC7.1)...
        pModuleInfo->SizeOfStruct = sizeof (IMAGEHLP_MODULE64_V2);
        memcpy (pData, pModuleInfo, sizeof (IMAGEHLP_MODULE64_V2));
        if (pSymGetModuleInfo64 (hProcess, baseAddr, (IMAGEHLP_MODULE64_V3 *)pData) != FALSE) {
            // only copy as much memory as is reserved...
            memcpy (pModuleInfo, pData, sizeof (IMAGEHLP_MODULE64_V2));
            pModuleInfo->SizeOfStruct = sizeof (IMAGEHLP_MODULE64_V2);
            return TRUE;
        }

        SetLastError (ERROR_DLL_INIT_FAILED);
        return FALSE;
    }

    HMODULE m_hDbhHelp;
    HANDLE m_hProcess;
    CHAR m_szSymPath[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
};

const wchar_t *StackWalker::Internal::dbg_help_path[] =
{ _T("\\Debugging Tools for Windows\\dbghelp.dll"),
#ifdef _M_IX86
  _T("\\Debugging Tools for Windows (x86)\\dbghelp.dll"),
#elif _M_X64
  _T("\\Debugging Tools for Windows (x64)\\dbghelp.dll"),
#elif _M_IA64
  _T("\\Debugging Tools for Windows (ia64)\\dbghelp.dll"),
#endif
#if defined _M_X64 || defined _M_IA64
  _T("\\Debugging Tools for Windows 64-Bit\\dbghelp.dll"),
#endif
  _T("") };

static void ArchSetup (const CONTEXT &c, STACKFRAME64 &s, DWORD &imageType) {
    // init STACKFRAME for first call
    memset (&s, 0, sizeof (s));
#ifdef _M_IX86
    // normally, call ImageNtHeader() and use machine info from PE header
    imageType = IMAGE_FILE_MACHINE_I386;
    s.AddrPC.Offset = c.Eip;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.Ebp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.Esp;
    s.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
    imageType = IMAGE_FILE_MACHINE_AMD64;
    s.AddrPC.Offset = c.Rip;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.Rsp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.Rsp;
    s.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
    imageType = IMAGE_FILE_MACHINE_IA64;
    s.AddrPC.Offset = c.StIIP;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.IntSp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrBStore.Offset = c.RsBSP;
    s.AddrBStore.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.IntSp;
    s.AddrStack.Mode = AddrModeFlat;
#else
#error "Platform not supported!"
#endif
}


void StackWalker::StrCpy(char *szDest, size_t nMaxDestSize, const char *szSrc) {
	if (nMaxDestSize <= 0)
		return;
	if (strlen(szSrc) < nMaxDestSize) {
		strcpy_s(szDest, nMaxDestSize, szSrc);
	}
	else {
		strncpy_s(szDest, nMaxDestSize, szSrc, nMaxDestSize);
		szDest[nMaxDestSize - 1] = 0;
	}
} // MyStrCpy

// #############################################################
StackWalker::StackWalker (DWORD dwProcessId, HANDLE hProcess) {
    m_options = OptionsAll;
    m_MaxStackDepth = 0;
    m_modulesLoaded = FALSE;
    m_hProcess = hProcess;
    m_dwProcessId = dwProcessId;
    m_szSymPath[0] = 0;
    m_MaxRecursionCount = 1000;
}
StackWalker::StackWalker (int options, int maxStackDepth, LPCSTR szSymPath, DWORD dwProcessId, HANDLE hProcess) {
    m_options = options;
    m_MaxStackDepth = maxStackDepth;
    m_modulesLoaded = FALSE;
    m_hProcess = hProcess;
    m_dwProcessId = dwProcessId;
    if (szSymPath != NULL) {
        strcpy_s (m_szSymPath, strlen (szSymPath) + 1, szSymPath);
        m_options |= SymBuildPath;
    } else {
        m_szSymPath[0] = 0;
    }

    m_MaxRecursionCount = 1000;
}

StackWalker::~StackWalker () {
}

BOOL StackWalker::LoadModules () {

    if (m_modulesLoaded != FALSE)
        return TRUE;

    // Build the sym-path:
    const size_t nSymPathLen = Parameter::STACKWALKER_MAX_TEMP_BUFFER;
    char szSymPath[nSymPathLen];
    szSymPath[0] = 0;

    if ((m_options & SymBuildPath) != 0) {
        // Now first add the (optional) provided sympath:
        if (m_szSymPath[0] != 0) {
            strcat_s (szSymPath, nSymPathLen, m_szSymPath);
            strcat_s (szSymPath, nSymPathLen, ";");
        }
        strcat_s (szSymPath, nSymPathLen, ".;");

        const size_t nTempLen = 1024;
        char szTemp[nTempLen];
        // Now add the current directory:
        if (GetCurrentDirectoryA (nTempLen, szTemp) > 0) {
            szTemp[nTempLen - 1] = 0;
            strcat_s (szSymPath, nSymPathLen, szTemp);
            strcat_s (szSymPath, nSymPathLen, ";");
        }

        // Now add the path for the main-module:
        if (GetModuleFileNameA (NULL, szTemp, nTempLen) > 0) {
            szTemp[nTempLen - 1] = 0;
            for (char *p = (szTemp + strlen (szTemp) - 1); p >= szTemp; --p) {
                // locate the rightmost path separator
                if ((*p == '\\') || (*p == '/') || (*p == ':')) {
                    *p = 0;
                    break;
                }
            } // for (search for path separator...)
            if (strlen (szTemp) > 0) {
                strcat_s (szSymPath, nSymPathLen, szTemp);
                strcat_s (szSymPath, nSymPathLen, ";");
            }
        }
        if (GetEnvironmentVariableA ("_NT_SYMBOL_PATH", szTemp, nTempLen) > 0) {
            szTemp[nTempLen - 1] = 0;
            strcat_s (szSymPath, nSymPathLen, szTemp);
            strcat_s (szSymPath, nSymPathLen, ";");
        }
        if (GetEnvironmentVariableA ("_NT_ALTERNATE_SYMBOL_PATH", szTemp, nTempLen) > 0) {
            szTemp[nTempLen - 1] = 0;
            strcat_s (szSymPath, nSymPathLen, szTemp);
            strcat_s (szSymPath, nSymPathLen, ";");
        }
        if (GetEnvironmentVariableA ("SYSTEMROOT", szTemp, nTempLen) > 0) {
            szTemp[nTempLen - 1] = 0;
            strcat_s (szSymPath, nSymPathLen, szTemp);
            strcat_s (szSymPath, nSymPathLen, ";");
            // also add the "system32"-directory:
            strcat_s (szTemp, nTempLen, "\\system32");
            strcat_s (szSymPath, nSymPathLen, szTemp);
            strcat_s (szSymPath, nSymPathLen, ";");
        }

        if ((m_options & SymUseSymSrv) != 0) {
            if (GetEnvironmentVariableA ("SYSTEMDRIVE", szTemp, nTempLen) > 0) {
                szTemp[nTempLen - 1] = 0;
                strcat_s (szSymPath, nSymPathLen, "SRV*");
                strcat_s (szSymPath, nSymPathLen, szTemp);
                strcat_s (szSymPath, nSymPathLen, "\\websymbols");
                strcat_s (szSymPath, nSymPathLen, "*http://msdl.microsoft.com/download/symbols;");
            } else
                strcat_s (szSymPath, nSymPathLen,
                          "SRV*c:\\websymbols*http://msdl.microsoft.com/"
                          "download/symbols;");
        }
    } // if SymBuildPath

    // First Init the whole stuff...
    BOOL bRet = internal ().Init (this, m_hProcess, szSymPath);

    if (bRet == FALSE) {
        OnDbgHelpErr ("Error while initializing dbghelp.dll", 0, 0);
        SetLastError (ERROR_DLL_INIT_FAILED);
        return FALSE;
    }

    bRet = internal ().LoadModules (this, m_hProcess, m_dwProcessId);
    if (bRet != FALSE)
        m_modulesLoaded = TRUE;
    return bRet;
}

// The following is used to pass the "userData"-Pointer to the user-provided
// readMemoryFunction This has to be done due to a problem with the
// "hProcess"-parameter in x64... Because this class is in no case
// multi-threading-enabled (because of the limitations of dbghelp.dll) it is
// "safe" to use a static-variable
static StackWalker::PReadProcessMemoryRoutine s_readMemoryFunction = NULL;
static LPVOID s_readMemoryFunction_UserData = NULL;

struct IMAGEHLP_SYMBOL64_WITH_NAME : IMAGEHLP_SYMBOL64 {
    static const size_t BUFFER_LEN = Parameter::STACKWALKER_MAX_NAMELEN;
    char buffer[BUFFER_LEN];
};

BOOL StackWalker::ShowCallstack (HANDLE hThread,
                                 const CONTEXT *context,
                                 PReadProcessMemoryRoutine readMemoryFunction,
                                 LPVOID pUserData) {
    CONTEXT c;
    CallstackEntry csEntry;
    IMAGEHLP_SYMBOL64_WITH_NAME sym;
    IMAGEHLP_MODULE64_V3 Module;
    IMAGEHLP_LINE64 Line;
    int frameNum;
    bool bLastEntryCalled = true;
    int curRecursionCount = 0;

    if (m_modulesLoaded == FALSE)
        LoadModules (); // ignore the result...

    if (internal ().m_hDbhHelp == NULL) {
        SetLastError (ERROR_DLL_INIT_FAILED);
        return FALSE;
    }

    s_readMemoryFunction = readMemoryFunction;
    s_readMemoryFunction_UserData = pUserData;

    if (context == NULL) {
        // If no context is provided, capture the context
        if (hThread == GetCurrentThread ()) {
            GET_CURRENT_CONTEXT (c, USED_CONTEXT_FLAGS);
        } else {
            SuspendThread (hThread);
            memset (&c, 0, sizeof (CONTEXT));
            c.ContextFlags = USED_CONTEXT_FLAGS;
            if (GetThreadContext (hThread, &c) == FALSE) {
                ResumeThread (hThread);
                return FALSE;
            }
        }
    } else
        c = *context;

    STACKFRAME64 s;
    DWORD imageType;
    ArchSetup (c, s, imageType);


    memset (&sym, 0, sizeof (IMAGEHLP_SYMBOL64_WITH_NAME));
    sym.SizeOfStruct = sizeof (IMAGEHLP_SYMBOL64);
    sym.MaxNameLength = Parameter::STACKWALKER_MAX_NAMELEN;

    memset (&Line, 0, sizeof (Line));
    Line.SizeOfStruct = sizeof (Line);

    memset (&Module, 0, sizeof (Module));
    Module.SizeOfStruct = sizeof (Module);

    for (frameNum = 0;; ++frameNum) {
        if (m_MaxStackDepth > 0 && frameNum >= m_MaxStackDepth)
            break;
        // get next stack frame (StackWalk64(), SymFunctionTableAccess64(),
        // SymGetModuleBase64()) if this returns ERROR_INVALID_ADDRESS (487) or
        // ERROR_NOACCESS (998), you can assume that either you are done, or
        // that the stack is so hosed that the next deeper frame could not be
        // found. CONTEXT need not to be supplied if imageTyp is
        // IMAGE_FILE_MACHINE_I386!
        if (!internal ().pStackWalk64 (imageType, m_hProcess, hThread, &s, &c, myReadProcMem,
                                       internal ().pSymFunctionTableAccess64,
                                       internal ().pSymGetModuleBase64, NULL)) {
            // INFO: "StackWalk64" does not set "GetLastError"...
            OnDbgHelpErr ("StackWalk64", 0, s.AddrPC.Offset);
            break;
        }

        csEntry.offset = s.AddrPC.Offset;
        csEntry.name[0] = 0;
        csEntry.undName[0] = 0;
        csEntry.undFullName[0] = 0;
        csEntry.offsetFromSmybol = 0;
        csEntry.offsetFromLine = 0;
        csEntry.lineFileName[0] = 0;
        csEntry.lineNumber = 0;
        csEntry.loadedImageName[0] = 0;
        csEntry.moduleName[0] = 0;
        if (s.AddrPC.Offset == s.AddrReturn.Offset) {
            if ((m_MaxRecursionCount > 0) && (curRecursionCount > m_MaxRecursionCount)) {
                OnDbgHelpErr ("StackWalk64-Endless-Callstack!", 0, s.AddrPC.Offset);
                break;
            }
            curRecursionCount++;
        } else
            curRecursionCount = 0;
        if ((m_options & RetrieveSymbol) && s.AddrPC.Offset != 0) {
            // we seem to have a valid PC
            // show procedure info (SymGetSymFromAddr64())
            if (internal ().pSymGetSymFromAddr64 (m_hProcess, s.AddrPC.Offset,
                                                  &(csEntry.offsetFromSmybol), &sym) != FALSE) {
                StrCpy (csEntry.name, Parameter::STACKWALKER_MAX_NAMELEN, sym.Name);

                internal ().pUnDecorateSymbolName (sym.Name, csEntry.undName,
                                                   Parameter::STACKWALKER_MAX_NAMELEN, UNDNAME_NAME_ONLY);
                internal ().pUnDecorateSymbolName (sym.Name, csEntry.undFullName,
                                                   Parameter::STACKWALKER_MAX_NAMELEN, UNDNAME_COMPLETE);
            } else {
                OnDbgHelpErr ("SymGetSymFromAddr64", GetLastError (), s.AddrPC.Offset);
            }

            // show line number info, NT5.0-method (SymGetLineFromAddr64())
            if ((m_options & RetrieveLineAndFile) && internal ().pSymGetLineFromAddr64 != NULL) { // yes, we have SymGetLineFromAddr64()
                if (internal ().pSymGetLineFromAddr64 (m_hProcess, s.AddrPC.Offset,
                                                       &(csEntry.offsetFromLine), &Line) != FALSE) {
                    csEntry.lineNumber = Line.LineNumber;
                    StrCpy (csEntry.lineFileName, Parameter::STACKWALKER_MAX_NAMELEN, Line.FileName);
                } else {
                    OnDbgHelpErr ("SymGetLineFromAddr64", GetLastError (), s.AddrPC.Offset);
                }
            } // yes, we have SymGetLineFromAddr64()

            // show module info (SymGetModuleInfo64())
            if ((m_options & RetrieveModuleInfo)) {
                if (internal ().GetModuleInfo (m_hProcess, s.AddrPC.Offset, &Module) != FALSE) { // got module info OK
                    switch (Module.SymType) {
                        case SymNone:
                            csEntry.symTypeString = "-nosymbols-";
                            break;
                        case SymCoff:
                            csEntry.symTypeString = "COFF";
                            break;
                        case SymCv:
                            csEntry.symTypeString = "CV";
                            break;
                        case SymPdb:
                            csEntry.symTypeString = "PDB";
                            break;
                        case SymExport:
                            csEntry.symTypeString = "-exported-";
                            break;
                        case SymDeferred:
                            csEntry.symTypeString = "-deferred-";
                            break;
                        case SymSym:
                            csEntry.symTypeString = "SYM";
                            break;
#if API_VERSION_NUMBER >= 9
                        case SymDia:
                            csEntry.symTypeString = "DIA";
                            break;
#endif
                        case 8: // SymVirtual:
                            csEntry.symTypeString = "Virtual";
                            break;
                        default:
                            //_snprintf( ty, sizeof ty, "symtype=%ld", (long)
                            // Module.SymType );
                            csEntry.symTypeString = NULL;
                            break;
                    }

                    StrCpy (csEntry.moduleName, Parameter::STACKWALKER_MAX_NAMELEN, Module.ModuleName);
                    csEntry.baseOfImage = Module.BaseOfImage;
                    StrCpy (csEntry.loadedImageName, Parameter::STACKWALKER_MAX_NAMELEN, Module.LoadedImageName);
                } // got module info OK
                else {
                    OnDbgHelpErr ("SymGetModuleInfo64", GetLastError (), s.AddrPC.Offset);
                }
            }
        } // we seem to have a valid PC

        CallstackEntryType et = nextEntry;
        if (frameNum == 0)
            et = firstEntry;
        bLastEntryCalled = false;
        OnCallstackEntry (et, csEntry);

        if (s.AddrReturn.Offset == 0) {
            bLastEntryCalled = true;
            OnCallstackEntry (lastEntry, csEntry);
            SetLastError (ERROR_SUCCESS);
            break;
        }
    } // for ( frameNum )

    if (bLastEntryCalled == false)
        OnCallstackEntry (lastEntry, csEntry);

    if (context == NULL)
        ResumeThread (hThread);

    return TRUE;
}

BOOL __stdcall StackWalker::myReadProcMem (HANDLE hProcess, DWORD64 qwBaseAddress, PVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead) {
    if (s_readMemoryFunction == NULL) {
        SIZE_T st;
        BOOL bRet = ReadProcessMemory (hProcess, (LPVOID)qwBaseAddress, lpBuffer, nSize, &st);
        *lpNumberOfBytesRead = (DWORD)st;
        // printf("ReadMemory: hProcess: %p, baseAddr: %p, buffer: %p, size: %d,
        // read: %d, result: %d\n", hProcess, (LPVOID) qwBaseAddress, lpBuffer,
        // nSize, (DWORD) st, (DWORD) bRet);
        return bRet;
    } else {
        return s_readMemoryFunction (hProcess, qwBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead,
                                     s_readMemoryFunction_UserData);
    }
}

