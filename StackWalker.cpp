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

	// SymCleanup()
	typedef BOOL(__stdcall *tSC) (IN HANDLE hProcess);
	tSC pSC;

	// SymFunctionTableAccess64()
	typedef PVOID(__stdcall *tSFTA) (HANDLE hProcess, DWORD64 AddrBase);
	tSFTA pSFTA;

	// SymGetLineFromAddr64()
	typedef BOOL(__stdcall *tSGLFA) (IN HANDLE hProcess, IN DWORD64 dwAddr, OUT PDWORD pdwDisplacement, OUT PIMAGEHLP_LINE64 Line);
	tSGLFA pSGLFA;

	// SymGetModuleBase64()
	typedef DWORD64(__stdcall *tSGMB) (IN HANDLE hProcess, IN DWORD64 dwAddr);
	tSGMB pSGMB;

	// SymGetModuleInfo64()
	typedef BOOL(__stdcall *tSGMI) (IN HANDLE hProcess, IN DWORD64 dwAddr, OUT IMAGEHLP_MODULE64_V3 *ModuleInfo);
	tSGMI pSGMI;

	// SymGetOptions()
	typedef DWORD(__stdcall *tSGO) (VOID);
	tSGO pSGO;

	// SymGetSymFromAddr64()
	typedef BOOL(__stdcall *tSGSFA) (IN HANDLE hProcess,
		IN DWORD64 dwAddr,
		OUT PDWORD64 pdwDisplacement,
		OUT PIMAGEHLP_SYMBOL64 Symbol);
	tSGSFA pSGSFA;

	// SymInitialize()
	typedef BOOL(__stdcall *tSI) (IN HANDLE hProcess, IN PSTR UserSearchPath, IN BOOL fInvadeProcess);
	tSI pSI;

	// SymLoadModule64()
	typedef DWORD64(__stdcall *tSLM) (IN HANDLE hProcess,
		IN HANDLE hFile,
		IN PSTR ImageName,
		IN PSTR ModuleName,
		IN DWORD64 BaseOfDll,
		IN DWORD SizeOfDll);
	tSLM pSLM;

	// SymSetOptions()
	typedef DWORD(__stdcall *tSSO) (IN DWORD SymOptions);
	tSSO pSSO;

	// StackWalk64()
	typedef BOOL(__stdcall *tSW) (DWORD MachineType,
		HANDLE hProcess,
		HANDLE hThread,
		LPSTACKFRAME64 StackFrame,
		PVOID ContextRecord,
		PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
		PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
		PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
		PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
	tSW pSW;

	// UnDecorateSymbolName()
	typedef DWORD(__stdcall WINAPI *tUDSN) (PCSTR DecoratedName, PSTR UnDecoratedName, DWORD UndecoratedLength, DWORD Flags);
	tUDSN pUDSN;

	typedef BOOL(__stdcall WINAPI *tSGSP) (HANDLE hProcess, PSTR SearchPath, DWORD SearchPathLength);
	tSGSP pSGSP;

	BOOL GetModuleListTH32(StackWalker *parent, HANDLE hProcess, DWORD pid) {
		// CreateToolhelp32Snapshot()
		typedef HANDLE(__stdcall * tCT32S) (DWORD dwFlags, DWORD th32ProcessID);
		// Module32First()
		typedef BOOL(__stdcall * tM32F) (HANDLE hSnapshot, LPMODULEENTRY32 lpme);
		// Module32Next()
		typedef BOOL(__stdcall * tM32N) (HANDLE hSnapshot, LPMODULEENTRY32 lpme);

		// try both dlls...
		const TCHAR *dllname[] = { _T("kernel32.dll"), _T("tlhelp32.dll") };
		HINSTANCE hToolhelp = NULL;
		tCT32S pCreateToolhelp32Snapshot = NULL;
		tM32F pModule32First = NULL;
		tM32N pModule32Next = NULL;

		HANDLE hSnapshot;
		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(moduleEntry);

		for (size_t i = 0; i < (sizeof(dllname) / sizeof(dllname[0])); i++) {
			hToolhelp = LoadLibrary(dllname[i]);
			if (hToolhelp == NULL)
				continue;
			pCreateToolhelp32Snapshot = (tCT32S)GetProcAddress(hToolhelp, "CreateToolhelp32Snapshot");
			pModule32First = (tM32F)GetProcAddress(hToolhelp, "Module32First");
			pModule32Next = (tM32N)GetProcAddress(hToolhelp, "Module32Next");
			if ((pCreateToolhelp32Snapshot != NULL) && (pModule32First != NULL) && (pModule32Next != NULL))
				break; // found the functions!
			FreeLibrary(hToolhelp);
			hToolhelp = NULL;
		}

		if (hToolhelp == NULL)
			return FALSE;

		hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if (hSnapshot == (HANDLE)-1) {
			FreeLibrary(hToolhelp);
			return FALSE;
		}

		BOOL keepGoing = !!pModule32First(hSnapshot, &moduleEntry);
		int cnt = 0;
		while (keepGoing) {
			LoadModule(parent, hProcess, moduleEntry.szExePath, moduleEntry.szModule, (DWORD64)moduleEntry.modBaseAddr, moduleEntry.modBaseSize);
			cnt++;
			keepGoing = !!pModule32Next(hSnapshot, &moduleEntry);
		}
		CloseHandle(hSnapshot);
		FreeLibrary(hToolhelp);
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

	BOOL GetModuleListPSAPI(StackWalker *parent, HANDLE hProcess) {
		// EnumProcessModules()
		typedef BOOL(__stdcall * tEPM) (HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded);
		// GetModuleFileNameEx()
		typedef DWORD(__stdcall * tGMFNE) (HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
		// GetModuleBaseName()
		typedef DWORD(__stdcall * tGMBN) (HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
		// GetModuleInformation()
		typedef BOOL(__stdcall * tGMI) (HANDLE hProcess, HMODULE hModule, LPMODULEINFO pmi, DWORD nSize);

		HINSTANCE hPsapi = LoadLibrary(_T("psapi.dll"));
		if (hPsapi == NULL)
			return FALSE;

		tEPM pEnumProcessModules;
		tGMFNE pGetModuleFileNameExA;
		tGMBN pGetModuleBaseNameA;
		tGMI pGetModuleInformation;

		DWORD cbNeeded;	
		HMODULE hMods[sizeof(HMODULE) * (STACKWALKER_MAX_TEMP_BUFFER / sizeof(HMODULE))];

		pEnumProcessModules = (tEPM)GetProcAddress(hPsapi, "EnumProcessModules");
		pGetModuleFileNameExA = (tGMFNE)GetProcAddress(hPsapi, "GetModuleFileNameExA");
		pGetModuleBaseNameA = (tGMFNE)GetProcAddress(hPsapi, "GetModuleBaseNameA");
		pGetModuleInformation = (tGMI)GetProcAddress(hPsapi, "GetModuleInformation");

		if ((pEnumProcessModules == NULL) || (pGetModuleFileNameExA == NULL) || (pGetModuleBaseNameA == NULL) || (pGetModuleInformation == NULL) ||
			!pEnumProcessModules(hProcess, hMods, STACKWALKER_MAX_TEMP_BUFFER, &cbNeeded) || cbNeeded > STACKWALKER_MAX_TEMP_BUFFER) {
			// we couldn't find all functions
			FreeLibrary(hPsapi);
			return FALSE;
		}

		char imageFileName[STACKWALKER_MAX_TEMP_BUFFER];
		char moduleFileName[STACKWALKER_MAX_TEMP_BUFFER];
		int count = 0;
		MODULEINFO moduleInfo;

		for (DWORD i = 0; i < cbNeeded / sizeof hMods[0]; i++) {
			// base address, size
			pGetModuleInformation(hProcess, hMods[i], &moduleInfo, sizeof moduleInfo);
			// image file name
			imageFileName[0] = 0;
			pGetModuleFileNameExA(hProcess, hMods[i], imageFileName, STACKWALKER_MAX_TEMP_BUFFER);
			// module name
			moduleFileName[0] = 0;
			pGetModuleBaseNameA(hProcess, hMods[i], moduleFileName, STACKWALKER_MAX_TEMP_BUFFER);

			DWORD dwRes = LoadModule(parent, hProcess, imageFileName, moduleFileName, (DWORD64)moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);
			if (dwRes != ERROR_SUCCESS)
				parent->OnDbgHelpErr("LoadModule", dwRes, 0);
			count++;
		}

		return count != 0;
	} // GetModuleListPSAPI

	DWORD LoadModule(StackWalker *parent, HANDLE hProcess, LPCSTR img, LPCSTR mod, DWORD64 baseAddr, DWORD size) {
		CHAR szImg[STACKWALKER_MAX_TEMP_BUFFER];// = _strdup(img);
		CHAR szMod[STACKWALKER_MAX_TEMP_BUFFER];// = _strdup(mod);
		DWORD result = ERROR_SUCCESS;
		if (pSLM(hProcess, 0, szImg, szMod, baseAddr, size) == 0)
		{
			return GetLastError();
		}
		
		ULONGLONG fileVersion = 0;
		if ((parent != NULL) && (szImg != NULL)) {
			// try to retrieve the file-version:
			if ((parent->m_options & StackWalker::RetrieveFileVersion) != 0) {
				VS_FIXEDFILEINFO *fInfo = NULL;
				DWORD dwHandle;
				DWORD dwSize = GetFileVersionInfoSizeA(szImg, &dwHandle);
				if (dwSize > 0) {
					LPVOID vData = malloc(dwSize);
					if (vData != NULL) {
						if (GetFileVersionInfoA(szImg, dwHandle, dwSize, vData) != 0) {
							UINT len;
							TCHAR szSubBlock[] = _T("\\");
							if (VerQueryValue(vData, szSubBlock, (LPVOID *)&fInfo, &len) == 0)
								fInfo = NULL;
							else {
								fileVersion = ((ULONGLONG)fInfo->dwFileVersionLS) +
									((ULONGLONG)fInfo->dwFileVersionMS << 32);
							}
						}
						free(vData);
					}
				}
			}

			if ((parent->m_options & StackWalker::RetrieveModuleInfo) != 0) {
				// Retrieve some additional-infos about the module
				IMAGEHLP_MODULE64_V3 Module;
				const char *szSymType = "-unknown-";
				if (GetModuleInfo(hProcess, baseAddr, &Module) != FALSE) {
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
				parent->OnLoadModule(img, mod, baseAddr, size, result, szSymType, pdbName, fileVersion);
			}
		}
		//if (szImg != NULL)
		//	free(szImg);
		//if (szMod != NULL)
		//	free(szMod);
		return result;
	}

	static const wchar_t * Internal::dbg_help_path[];

	void DeInit(StackWalker *parent) {
		if (pSC != NULL)
			pSC(m_hProcess); // SymCleanup
		if (m_hDbhHelp != NULL)
			FreeLibrary(m_hDbhHelp);
		m_hDbhHelp = NULL;
		parent = NULL;
	}

	BOOL Init(StackWalker *parent, HANDLE hProcess, LPCSTR szSymPath) {

		static_assert(sizeof(Internal) < STACKWALKERINTERNAL_STRUCT_SIZE, "Increase buffer size");

		if (parent == NULL)
			return FALSE;

		m_hDbhHelp = NULL;
		pSC = NULL;
		m_hProcess = hProcess;
		m_szSymPath[0] = 0;
		pSFTA = NULL;
		pSGLFA = NULL;
		pSGMB = NULL;
		pSGMI = NULL;
		pSGO = NULL;
		pSGSFA = NULL;
		pSI = NULL;
		pSLM = NULL;
		pSSO = NULL;
		pSW = NULL;
		pUDSN = NULL;
		pSGSP = NULL;

		// Dynamically load the Entry-Points for dbghelp.dll:
		// First try to load the newest one from
		TCHAR szTemp[StackWalker::STACKWALKER_MAX_TEMP_BUFFER];
		// But before we do this, we first check if the ".local" file exists
		if (GetModuleFileName(NULL, szTemp, StackWalker::STACKWALKER_MAX_TEMP_BUFFER) > 0) {
			_tcscat_s(szTemp, _T(".local"));
			if (GetFileAttributes(szTemp) == INVALID_FILE_ATTRIBUTES) {
				// ".local" file does not exist, so we can try to load the dbghelp.dll from the
				// "Debugging Tools for Windows" Ok, first try the new path according to the
				// architecture:
				DWORD result = GetEnvironmentVariable(_T("ProgramFiles"), szTemp, StackWalker::STACKWALKER_MAX_TEMP_BUFFER);
				int idx = 0;
				while (result > 0 && dbg_help_path[idx][0] != 0)
				{
					_tcscat_s(szTemp, dbg_help_path[idx]);
					// now check if the file exists:
					if (GetFileAttributes(szTemp) != INVALID_FILE_ATTRIBUTES)
					{
						m_hDbhHelp = LoadLibrary(szTemp);
						break;
					}
					idx++;
				}
			}
		}
		if (m_hDbhHelp == NULL) // if not already loaded, try to load a default-one
			m_hDbhHelp = LoadLibrary(_T("dbghelp.dll"));
		if (m_hDbhHelp == NULL)
			return FALSE;
		pSI = (tSI)GetProcAddress(m_hDbhHelp, "SymInitialize");
		pSC = (tSC)GetProcAddress(m_hDbhHelp, "SymCleanup");

		pSW = (tSW)GetProcAddress(m_hDbhHelp, "StackWalk64");
		pSGO = (tSGO)GetProcAddress(m_hDbhHelp, "SymGetOptions");
		pSSO = (tSSO)GetProcAddress(m_hDbhHelp, "SymSetOptions");

		pSFTA = (tSFTA)GetProcAddress(m_hDbhHelp, "SymFunctionTableAccess64");
		pSGLFA = (tSGLFA)GetProcAddress(m_hDbhHelp, "SymGetLineFromAddr64");
		pSGMB = (tSGMB)GetProcAddress(m_hDbhHelp, "SymGetModuleBase64");
		pSGMI = (tSGMI)GetProcAddress(m_hDbhHelp, "SymGetModuleInfo64");
		pSGSFA = (tSGSFA)GetProcAddress(m_hDbhHelp, "SymGetSymFromAddr64");
		pUDSN = (tUDSN)GetProcAddress(m_hDbhHelp, "UnDecorateSymbolName");
		pSLM = (tSLM)GetProcAddress(m_hDbhHelp, "SymLoadModule64");
		pSGSP = (tSGSP)GetProcAddress(m_hDbhHelp, "SymGetSearchPath");

		if (pSC == NULL || pSFTA == NULL || pSGMB == NULL || pSGMI == NULL || pSGO == NULL ||
			pSGSFA == NULL || pSI == NULL || pSSO == NULL || pSW == NULL || pUDSN == NULL || pSLM == NULL) {
			FreeLibrary(m_hDbhHelp);
			m_hDbhHelp = NULL;
			pSC = NULL;
			return FALSE;
		}

		// SymInitialize
		if (szSymPath != NULL && szSymPath[0] != 0)
			strcpy_s(m_szSymPath, strlen(szSymPath) + 1, szSymPath);
		if (pSI(m_hProcess, m_szSymPath, FALSE) == FALSE)
			parent->OnDbgHelpErr("SymInitialize", GetLastError(), 0);

		DWORD symOptions = pSGO(); // SymGetOptions
		symOptions |= SYMOPT_LOAD_LINES;
		symOptions |= SYMOPT_FAIL_CRITICAL_ERRORS;
		// symOptions |= SYMOPT_NO_PROMPTS;
		// SymSetOptions
		symOptions = pSSO(symOptions);

		char buf[StackWalker::STACKWALKER_MAX_NAMELEN] = { 0 };
		if (pSGSP != NULL) {
			if (pSGSP(m_hProcess, buf, StackWalker::STACKWALKER_MAX_NAMELEN) == FALSE)
				parent->OnDbgHelpErr("SymGetSearchPath", GetLastError(), 0);
		}
		if (parent->m_options & StackWalker::RetrieveSystemInfo)
		{
			char szUserName[1024] = { 0 };
			DWORD dwSize = 1024;
			GetUserNameA(szUserName, &dwSize);
			parent->OnSymInit(buf, symOptions, szUserName);
		}
		return TRUE;
	}
	BOOL LoadModules(StackWalker *parent, HANDLE hProcess, DWORD dwProcessId) {
		// first try toolhelp32
		if (GetModuleListTH32(parent, hProcess, dwProcessId))
			return true;
		// then try psapi
		return GetModuleListPSAPI(parent, hProcess);
	}

	BOOL GetModuleInfo(HANDLE hProcess, DWORD64 baseAddr, IMAGEHLP_MODULE64_V3 *pModuleInfo) {
		memset(pModuleInfo, 0, sizeof(IMAGEHLP_MODULE64_V3));
		if (pSGMI == NULL) {
			SetLastError(ERROR_DLL_INIT_FAILED);
			return FALSE;
		}
		// First try to use the larger ModuleInfo-Structure
		pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V3);
		char pData[sizeof(IMAGEHLP_MODULE64_V3)*2]; // reserve enough memory, so the bug in
													// v6.3.5.1 does not lead to
													// memory-overwrites...

		memcpy(pData, pModuleInfo, sizeof(IMAGEHLP_MODULE64_V3));
		static bool s_useV3Version = true;
		if (s_useV3Version) {
			if (pSGMI(hProcess, baseAddr, (IMAGEHLP_MODULE64_V3 *)pData) != FALSE) {
				// only copy as much memory as is reserved...
				memcpy(pModuleInfo, pData, sizeof(IMAGEHLP_MODULE64_V3));
				pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V3);
				return TRUE;
			}
			s_useV3Version = false; // to prevent unnecessary calls with the larger struct...
		}

		// could not retrieve the bigger structure, try with the smaller one (as
		// defined in VC7.1)...
		pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V2);
		memcpy(pData, pModuleInfo, sizeof(IMAGEHLP_MODULE64_V2));
		if (pSGMI(hProcess, baseAddr, (IMAGEHLP_MODULE64_V3 *)pData) != FALSE) {
			// only copy as much memory as is reserved...
			memcpy(pModuleInfo, pData, sizeof(IMAGEHLP_MODULE64_V2));
			pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V2);
			return TRUE;
		}

		SetLastError(ERROR_DLL_INIT_FAILED);
		return FALSE;
		}

	HMODULE m_hDbhHelp;
	HANDLE m_hProcess;
	CHAR m_szSymPath[StackWalker::STACKWALKER_MAX_TEMP_BUFFER];

};

const wchar_t * StackWalker::Internal::dbg_help_path[] = {
	_T("\\Debugging Tools for Windows\\dbghelp.dll"),
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
	_T("")
};

static void ArchSetup(const CONTEXT &c, STACKFRAME64 &s, DWORD &imageType) {
	// init STACKFRAME for first call
	memset(&s, 0, sizeof(s));
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


static void MyStrCpy (char *szDest, size_t nMaxDestSize, const char *szSrc) {
    if (nMaxDestSize <= 0)
        return;
    if (strlen (szSrc) < nMaxDestSize) {
        strcpy_s (szDest, nMaxDestSize, szSrc);
    } else {
        strncpy_s (szDest, nMaxDestSize, szSrc, nMaxDestSize);
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
    const size_t nSymPathLen = STACKWALKER_MAX_TEMP_BUFFER;
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
    BOOL bRet = internal().Init(this, m_hProcess, szSymPath);

    if (bRet == FALSE) {
        OnDbgHelpErr ("Error while initializing dbghelp.dll", 0, 0);
        SetLastError (ERROR_DLL_INIT_FAILED);
        return FALSE;
    }

    bRet = internal().LoadModules(this, m_hProcess, m_dwProcessId);
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
    static const size_t BUFFER_LEN = StackWalker::STACKWALKER_MAX_NAMELEN;
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

    if (internal().m_hDbhHelp == NULL) {
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
	ArchSetup(c, s, imageType);


    memset (&sym, 0, sizeof (IMAGEHLP_SYMBOL64_WITH_NAME));
    sym.SizeOfStruct = sizeof (IMAGEHLP_SYMBOL64);
    sym.MaxNameLength = STACKWALKER_MAX_NAMELEN;

	memset(&Line, 0, sizeof(Line));
	Line.SizeOfStruct = sizeof(Line);

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
        if (!internal().pSW (imageType, m_hProcess, hThread, &s, &c, myReadProcMem,
			internal().pSFTA, internal().pSGMB, NULL)) {
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
            if (internal().pSGSFA (m_hProcess, s.AddrPC.Offset, &(csEntry.offsetFromSmybol), &sym) != FALSE) {
                MyStrCpy (csEntry.name, STACKWALKER_MAX_NAMELEN, sym.Name);
                // UnDecorateSymbolName()
                internal().pUDSN (sym.Name, csEntry.undName, STACKWALKER_MAX_NAMELEN, UNDNAME_NAME_ONLY);
                internal().pUDSN (sym.Name, csEntry.undFullName, STACKWALKER_MAX_NAMELEN, UNDNAME_COMPLETE);
            } else {
                OnDbgHelpErr ("SymGetSymFromAddr64", GetLastError (), s.AddrPC.Offset);
            }

            // show line number info, NT5.0-method (SymGetLineFromAddr64())
            if ( (m_options & RetrieveLineAndFile) && internal().pSGLFA != NULL) { // yes, we have SymGetLineFromAddr64()
                if (internal().pSGLFA (m_hProcess, s.AddrPC.Offset,
                                        &(csEntry.offsetFromLine), &Line) != FALSE) {
                    csEntry.lineNumber = Line.LineNumber;
                    MyStrCpy (csEntry.lineFileName, STACKWALKER_MAX_NAMELEN, Line.FileName);
                } else {
                    OnDbgHelpErr ("SymGetLineFromAddr64", GetLastError (), s.AddrPC.Offset);
                }
            } // yes, we have SymGetLineFromAddr64()

            // show module info (SymGetModuleInfo64())
			if ((m_options & RetrieveModuleInfo))
			{
				if (internal().GetModuleInfo(m_hProcess, s.AddrPC.Offset, &Module) != FALSE) { // got module info OK
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

					MyStrCpy(csEntry.moduleName, STACKWALKER_MAX_NAMELEN, Module.ModuleName);
					csEntry.baseOfImage = Module.BaseOfImage;
					MyStrCpy(csEntry.loadedImageName, STACKWALKER_MAX_NAMELEN, Module.LoadedImageName);
				} // got module info OK
				else {
					OnDbgHelpErr("SymGetModuleInfo64", GetLastError(), s.AddrPC.Offset);
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

void StackWalker::OnLoadModule (LPCSTR img,
                                LPCSTR mod,
                                DWORD64 baseAddr,
                                DWORD size,
                                DWORD result,
                                LPCSTR symType,
                                LPCSTR pdbName,
                                ULONGLONG fileVersion) {
    CHAR buffer[STACKWALKER_MAX_NAMELEN];
    if (fileVersion == 0)
        _snprintf_s (buffer, STACKWALKER_MAX_NAMELEN, "%s:%s (%p), size: %d (result: %d), SymType: '%s', PDB: '%s'\n",
                     img, mod, (LPVOID)baseAddr, size, result, symType, pdbName);
    else {
        DWORD v4 = (DWORD) (fileVersion & 0xFFFF);
        DWORD v3 = (DWORD) ((fileVersion >> 16) & 0xFFFF);
        DWORD v2 = (DWORD) ((fileVersion >> 32) & 0xFFFF);
        DWORD v1 = (DWORD) ((fileVersion >> 48) & 0xFFFF);
        _snprintf_s (buffer, STACKWALKER_MAX_NAMELEN,
                     "%s:%s (%p), size: %d (result: %d), SymType: '%s', PDB: '%s', "
                     "fileVersion: %d.%d.%d.%d\n",
                     img, mod, (LPVOID)baseAddr, size, result, symType, pdbName, v1, v2, v3, v4);
    }
    OnOutput (buffer);
}

void StackWalker::OnCallstackEntry (CallstackEntryType eType, CallstackEntry &entry) {
    CHAR buffer[STACKWALKER_MAX_NAMELEN];
    if ((eType != lastEntry) && (entry.offset != 0)) {
        if (entry.name[0] == 0)
            MyStrCpy (entry.name, STACKWALKER_MAX_NAMELEN, "(function-name not available)");
        if (entry.undName[0] != 0)
            MyStrCpy (entry.name, STACKWALKER_MAX_NAMELEN, entry.undName);
        if (entry.undFullName[0] != 0)
            MyStrCpy (entry.name, STACKWALKER_MAX_NAMELEN, entry.undFullName);
        if (entry.lineFileName[0] == 0) {
            MyStrCpy (entry.lineFileName, STACKWALKER_MAX_NAMELEN, "(filename not available)");
            if (entry.moduleName[0] == 0)
                MyStrCpy (entry.moduleName, STACKWALKER_MAX_NAMELEN, "(module-name not available)");
            _snprintf_s (buffer, STACKWALKER_MAX_NAMELEN, "%p (%s): %s: %s\n", (LPVOID)entry.offset,
                         entry.moduleName, entry.lineFileName, entry.name);
        } else
            _snprintf_s (buffer, STACKWALKER_MAX_NAMELEN, "%s (%d): %s\n", entry.lineFileName,
                         entry.lineNumber, entry.name);
        buffer[STACKWALKER_MAX_NAMELEN - 1] = 0;
        OnOutput (buffer);
    }
}

void StackWalker::OnDbgHelpErr (LPCSTR szFuncName, DWORD gle, DWORD64 addr) {
    CHAR buffer[STACKWALKER_MAX_NAMELEN];
    _snprintf_s (buffer, STACKWALKER_MAX_NAMELEN, "ERROR: %s, GetLastError: %d (Address: %p)\n",
                 szFuncName, gle, (LPVOID)addr);
    OnOutput (buffer);
}

void StackWalker::OnSymInit (LPCSTR szSearchPath, DWORD symOptions, LPCSTR szUserName) {
    CHAR buffer[STACKWALKER_MAX_NAMELEN];
    _snprintf_s (buffer, STACKWALKER_MAX_NAMELEN, "SymInit: Symbol-SearchPath: '%s', symOptions: %d, UserName: '%s'\n",
                 szSearchPath, symOptions, szUserName);
    OnOutput (buffer);
// Also display the OS-version
#if _MSC_VER <= 1200
    OSVERSIONINFOA ver;
    ZeroMemory (&ver, sizeof (OSVERSIONINFOA));
    ver.dwOSVersionInfoSize = sizeof (ver);
    if (GetVersionExA (&ver) != FALSE) {
        _snprintf_s (buffer, STACKWALKER_MAX_NAMELEN, "OS-Version: %d.%d.%d (%s)\n",
                     ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber, ver.szCSDVersion);
        OnOutput (buffer);
    }
#else
    OSVERSIONINFOEXA ver;
    ZeroMemory (&ver, sizeof (OSVERSIONINFOEXA));
    ver.dwOSVersionInfoSize = sizeof (ver);
    if (GetVersionExA ((OSVERSIONINFOA *)&ver) != FALSE) {
        _snprintf_s (buffer, STACKWALKER_MAX_NAMELEN, "OS-Version: %d.%d.%d (%s) 0x%x-0x%x\n",
                     ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber, ver.szCSDVersion,
                     ver.wSuiteMask, ver.wProductType);
        OnOutput (buffer);
    }
#endif
}

void StackWalker::OnOutput (LPCSTR buffer) {
    OutputDebugStringA (buffer);
}
