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
*   Redistribution and use in source and binary forms, with or without
*   modification, are permitted provided that the following conditions are met:
*
*   Redistributions of source code must retain the above copyright notice,
*   this list of conditions and the following disclaimer.
*   Redistributions in binary form must reproduce the above copyright notice,
*   this list of conditions and the following disclaimer in the documentation
*   and/or other materials provided with the distribution.
*   Neither the name of Jochen Kalmbach nor the names of its contributors may
*   be used to endorse or promote products derived from this software without
*   specific prior written permission.
*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
*   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
*   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
*   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
*   BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
*   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
*   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
*   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
*   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
*   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
*   POSSIBILITY OF SUCH DAMAGE.
*
**********************************************************************/
#include "pch/pch.hpp"

const wchar_t * StackWalkerInternal::dbg_help_path[] = {
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

StackWalkerInternal::StackWalkerInternal(StackWalker *parent, HANDLE hProcess) {
	m_parent = parent;
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
}

StackWalkerInternal::~StackWalkerInternal() {
	if (pSC != NULL)
		pSC(m_hProcess); // SymCleanup
	if (m_hDbhHelp != NULL)
		FreeLibrary(m_hDbhHelp);
	m_hDbhHelp = NULL;
	m_parent = NULL;
}

BOOL StackWalkerInternal::Init(LPCSTR szSymPath) {
	if (m_parent == NULL)
		return FALSE;
	// Dynamically load the Entry-Points for dbghelp.dll:
	// First try to load the newest one from
	TCHAR szTemp[StackWalker::STACKWALK_MAX_TEMP_BUFFER];
	// But before we do this, we first check if the ".local" file exists
	if (GetModuleFileName(NULL, szTemp, StackWalker::STACKWALK_MAX_TEMP_BUFFER) > 0) {
		_tcscat_s(szTemp, _T(".local"));
		if (GetFileAttributes(szTemp) == INVALID_FILE_ATTRIBUTES) {
			// ".local" file does not exist, so we can try to load the dbghelp.dll from the
			// "Debugging Tools for Windows" Ok, first try the new path according to the
			// architecture:
			DWORD result = GetEnvironmentVariable(_T("ProgramFiles"), szTemp, StackWalker::STACKWALK_MAX_TEMP_BUFFER);
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
	if (this->pSI(m_hProcess, m_szSymPath, FALSE) == FALSE)
		this->m_parent->OnDbgHelpErr("SymInitialize", GetLastError(), 0);

	DWORD symOptions = this->pSGO(); // SymGetOptions
	symOptions |= SYMOPT_LOAD_LINES;
	symOptions |= SYMOPT_FAIL_CRITICAL_ERRORS;
	// symOptions |= SYMOPT_NO_PROMPTS;
	// SymSetOptions
	symOptions = this->pSSO(symOptions);

	char buf[StackWalker::STACKWALK_MAX_NAMELEN] = { 0 };
	if (this->pSGSP != NULL) {
		if (this->pSGSP(m_hProcess, buf, StackWalker::STACKWALK_MAX_NAMELEN) == FALSE)
			this->m_parent->OnDbgHelpErr("SymGetSearchPath", GetLastError(), 0);
	}
	if (this->m_parent->m_options & StackWalker::RetrieveSystemInfo)
	{
		char szUserName[1024] = { 0 };
		DWORD dwSize = 1024;
		GetUserNameA(szUserName, &dwSize);
		this->m_parent->OnSymInit(buf, symOptions, szUserName);
	}
	return TRUE;
}

BOOL StackWalkerInternal::GetModuleListTH32(HANDLE hProcess, DWORD pid) {
		// CreateToolhelp32Snapshot()
		typedef HANDLE(__stdcall * tCT32S) (DWORD dwFlags, DWORD th32ProcessID);
		// Module32First()
		typedef BOOL(__stdcall * tM32F) (HANDLE hSnapshot, LPMODULEENTRY32 lpme);
		// Module32Next()
		typedef BOOL(__stdcall * tM32N) (HANDLE hSnapshot, LPMODULEENTRY32 lpme);

		// try both dlls...
		const TCHAR *dllname[] = { _T("kernel32.dll"), _T("tlhelp32.dll") };
		HINSTANCE hToolhelp = NULL;
		tCT32S pCT32S = NULL;
		tM32F pM32F = NULL;
		tM32N pM32N = NULL;

		HANDLE hSnap;
		MODULEENTRY32 me;
		me.dwSize = sizeof(me);
		BOOL keepGoing;
		size_t i;

		for (i = 0; i < (sizeof(dllname) / sizeof(dllname[0])); i++) {
			hToolhelp = LoadLibrary(dllname[i]);
			if (hToolhelp == NULL)
				continue;
			pCT32S = (tCT32S)GetProcAddress(hToolhelp, "CreateToolhelp32Snapshot");
			pM32F = (tM32F)GetProcAddress(hToolhelp, "Module32First");
			pM32N = (tM32N)GetProcAddress(hToolhelp, "Module32Next");
			if ((pCT32S != NULL) && (pM32F != NULL) && (pM32N != NULL))
				break; // found the functions!
			FreeLibrary(hToolhelp);
			hToolhelp = NULL;
		}

		if (hToolhelp == NULL)
			return FALSE;

		hSnap = pCT32S(TH32CS_SNAPMODULE, pid);
		if (hSnap == (HANDLE)-1) {
			FreeLibrary(hToolhelp);
			return FALSE;
		}

		keepGoing = !!pM32F(hSnap, &me);
		int cnt = 0;
		while (keepGoing) {
			this->LoadModule(hProcess, me.szExePath, me.szModule, (DWORD64)me.modBaseAddr, me.modBaseSize);
			cnt++;
			keepGoing = !!pM32N(hSnap, &me);
		}
		CloseHandle(hSnap);
		FreeLibrary(hToolhelp);
		if (cnt <= 0)
			return FALSE;
		return TRUE;
	} // GetModuleListTH32


BOOL StackWalkerInternal::GetModuleListPSAPI(HANDLE hProcess) {
		// EnumProcessModules()
		typedef BOOL(__stdcall * tEPM) (HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded);
		// GetModuleFileNameEx()
		typedef DWORD(__stdcall * tGMFNE) (HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
		// GetModuleBaseName()
		typedef DWORD(__stdcall * tGMBN) (HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
		// GetModuleInformation()
		typedef BOOL(__stdcall * tGMI) (HANDLE hProcess, HMODULE hModule, LPMODULEINFO pmi, DWORD nSize);

		HINSTANCE hPsapi;
		tEPM pEPM;
		tGMFNE pGMFNE;
		tGMBN pGMBN;
		tGMI pGMI;

		DWORD i;
		// ModuleEntry e;
		DWORD cbNeeded;
		MODULEINFO mi;
		const SIZE_T TTBUFLEN = 8096;
		HMODULE hMods[sizeof(HMODULE) * (TTBUFLEN / sizeof(HMODULE))];

		int cnt = 0;

		hPsapi = LoadLibrary(_T("psapi.dll"));
		if (hPsapi == NULL)
			return FALSE;

		pEPM = (tEPM)GetProcAddress(hPsapi, "EnumProcessModules");
		pGMFNE = (tGMFNE)GetProcAddress(hPsapi, "GetModuleFileNameExA");
		pGMBN = (tGMFNE)GetProcAddress(hPsapi, "GetModuleBaseNameA");
		pGMI = (tGMI)GetProcAddress(hPsapi, "GetModuleInformation");

		if ((pEPM == NULL) || (pGMFNE == NULL) || (pGMBN == NULL) || (pGMI == NULL) ||
			!pEPM(hProcess, hMods, TTBUFLEN, &cbNeeded) || cbNeeded > TTBUFLEN) {
			// we couldn't find all functions
			FreeLibrary(hPsapi);
			return FALSE;
		}

		char tt[TTBUFLEN];
		char tt2[TTBUFLEN];

		for (i = 0; i < cbNeeded / sizeof hMods[0]; i++) {
			// base address, size
			pGMI(hProcess, hMods[i], &mi, sizeof mi);
			// image file name
			tt[0] = 0;
			pGMFNE(hProcess, hMods[i], tt, TTBUFLEN);
			// module name
			tt2[0] = 0;
			pGMBN(hProcess, hMods[i], tt2, TTBUFLEN);

			DWORD dwRes = this->LoadModule(hProcess, tt, tt2, (DWORD64)mi.lpBaseOfDll, mi.SizeOfImage);
			if (dwRes != ERROR_SUCCESS)
				this->m_parent->OnDbgHelpErr("LoadModule", dwRes, 0);
			cnt++;
		}

		return cnt != 0;
	} // GetModuleListPSAPI

	DWORD StackWalkerInternal::LoadModule(HANDLE hProcess, LPCSTR img, LPCSTR mod, DWORD64 baseAddr, DWORD size) {
		CHAR *szImg = _strdup(img);
		CHAR *szMod = _strdup(mod);
		DWORD result = ERROR_SUCCESS;
		if ((szImg == NULL) || (szMod == NULL))
			result = ERROR_NOT_ENOUGH_MEMORY;
		else {
			if (pSLM(hProcess, 0, szImg, szMod, baseAddr, size) == 0)
				result = GetLastError();
		}
		ULONGLONG fileVersion = 0;
		if ((m_parent != NULL) && (szImg != NULL)) {
			// try to retrieve the file-version:
			if ((this->m_parent->m_options & StackWalker::RetrieveFileVersion) != 0) {
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

			if ((this->m_parent->m_options & StackWalker::RetrieveModuleInfo) != 0) {
				// Retrive some additional-infos about the module
				IMAGEHLP_MODULE64_V3 Module;
				const char *szSymType = "-unknown-";
				if (this->GetModuleInfo(hProcess, baseAddr, &Module) != FALSE) {
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
				this->m_parent->OnLoadModule(img, mod, baseAddr, size, result, szSymType, pdbName, fileVersion);
			}
		}
		if (szImg != NULL)
			free(szImg);
		if (szMod != NULL)
			free(szMod);
		return result;
	}

	BOOL StackWalkerInternal::LoadModules(HANDLE hProcess, DWORD dwProcessId) {
		// first try toolhelp32
		if (GetModuleListTH32(hProcess, dwProcessId))
			return true;
		// then try psapi
		return GetModuleListPSAPI(hProcess);
	}

	BOOL StackWalkerInternal::GetModuleInfo(HANDLE hProcess, DWORD64 baseAddr, IMAGEHLP_MODULE64_V3 *pModuleInfo) {
		memset(pModuleInfo, 0, sizeof(IMAGEHLP_MODULE64_V3));
		if (this->pSGMI == NULL) {
			SetLastError(ERROR_DLL_INIT_FAILED);
			return FALSE;
		}
		// First try to use the larger ModuleInfo-Structure
		pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V3);
		char pData[StackWalker::STACKWALK_MAX_TEMP_BUFFER]; // reserve enough memory, so the bug in
															// v6.3.5.1 does not lead to
															// memory-overwrites...

		memcpy(pData, pModuleInfo, sizeof(IMAGEHLP_MODULE64_V3));
		static bool s_useV3Version = true;
		if (s_useV3Version) {
			if (this->pSGMI(hProcess, baseAddr, (IMAGEHLP_MODULE64_V3 *)pData) != FALSE) {
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
		if (this->pSGMI(hProcess, baseAddr, (IMAGEHLP_MODULE64_V3 *)pData) != FALSE) {
			// only copy as much memory as is reserved...
			memcpy(pModuleInfo, pData, sizeof(IMAGEHLP_MODULE64_V2));
			pModuleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64_V2);
			return TRUE;
		}

		SetLastError(ERROR_DLL_INIT_FAILED);
		return FALSE;
	}

	void StackWalkerInternal::ArchSetup(const CONTEXT &c, STACKFRAME64 &s, DWORD &imageType) {
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