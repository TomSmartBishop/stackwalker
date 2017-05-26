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


// Some missing defines (for VC5/6):
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif

// secure-CRT_functions are only available starting with VC8
#if _MSC_VER < 1400
#define strcpy_s(dst, len, src) strcpy (dst, src)
#define strncpy_s(dst, len, src, maxLen) strncpy (dst, len, src)
#define strcat_s(dst, len, src) strcat (dst, src)
#define _snprintf_s _snprintf
#define _tcscat_s _tcscat
#endif

// The "ugly" assembler-implementation is needed for systems before XP
// If you have a new PSDK and you only compile for XP and later, then you can
// use the "RtlCaptureContext" Currently there is no define which determines the
// PSDK-Version... So we just use the compiler-version (and assumes that the
// PSDK is the one which was installed by the VS-IDE)

// INFO: If you want, you can use the RtlCaptureContext if you only target XP
// and later...
//       But I currently use it in x64/IA64 environments...
//#if defined(_M_IX86) && (_WIN32_WINNT <= 0x0500) && (_MSC_VER < 1400)

#if defined(_M_IX86)
#ifdef CURRENT_THREAD_VIA_EXCEPTION
// TODO: The following is not a "good" implementation,
// because the callstack is only valid in the "__except" block...
#define GET_CURRENT_CONTEXT(c, contextFlags)                                                                 \
    do {                                                                                                     \
        memset (&c, 0, sizeof (CONTEXT));                                                                    \
        EXCEPTION_POINTERS *pExp = NULL;                                                                     \
        __try {                                                                                              \
            throw 0;                                                                                         \
        \
} __except (((pExp = GetExceptionInformation ()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_EXECUTE_HANDLER)) { \
        }                                                                                                    \
        if (pExp != NULL)                                                                                    \
            memcpy (&c, pExp->ContextRecord, sizeof (CONTEXT));                                              \
        c.ContextFlags = contextFlags;                                                                       \
    } while (0);
#else
// The following should be enough for walking the callstack...
#define GET_CURRENT_CONTEXT(c, contextFlags)                                                          \
    do {                                                                                              \
        memset (&c, 0, sizeof (CONTEXT));                                                             \
        c.ContextFlags = contextFlags;                                                                \
        __asm call x __asm x : pop eax __asm mov c.Eip, eax __asm mov c.Ebp, ebp __asm mov c.Esp, esp \
    } while (0);
#endif

#else

// The following is defined for x86 (XP and higher), x64 and IA64:
#define GET_CURRENT_CONTEXT(c, contextFlags)                                                       \
    do {                                                                                           \
        memset (&c, 0, sizeof (CONTEXT));                                                          \
        c.ContextFlags = contextFlags;                                                             \
        RtlCaptureContext (&c);                                                                    \
    } while (0);
#endif


// Normally it should be enough to use 'CONTEXT_FULL' (better would be
// 'CONTEXT_ALL')
#define USED_CONTEXT_FLAGS CONTEXT_FULL


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
    this->m_options = OptionsAll;
	this->m_MaxStackDepth = 0;
    this->m_modulesLoaded = FALSE;
    this->m_hProcess = hProcess;
    this->m_sw = new StackWalkerInternal (this, this->m_hProcess);
    this->m_dwProcessId = dwProcessId;
    this->m_szSymPath[0] = 0;
    this->m_MaxRecursionCount = 1000;
}
StackWalker::StackWalker (int options, int maxStackDepth, LPCSTR szSymPath, DWORD dwProcessId, HANDLE hProcess) {
    this->m_options = options;
	this->m_MaxStackDepth = maxStackDepth;
    this->m_modulesLoaded = FALSE;
    this->m_hProcess = hProcess;
    this->m_sw = new StackWalkerInternal (this, this->m_hProcess);
    this->m_dwProcessId = dwProcessId;
    if (szSymPath != NULL) {
        strcpy_s (this->m_szSymPath, strlen (szSymPath) + 1, szSymPath);
        this->m_options |= SymBuildPath;
    } else {
        this->m_szSymPath[0] = 0;
    }

    this->m_MaxRecursionCount = 1000;
}

StackWalker::~StackWalker () {
    if (this->m_sw != NULL)
        delete this->m_sw;
    this->m_sw = NULL;
}

BOOL StackWalker::LoadModules () {
    if (this->m_sw == NULL) {
        SetLastError (ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
    if (m_modulesLoaded != FALSE)
        return TRUE;

    // Build the sym-path:
    const size_t nSymPathLen = STACKWALK_MAX_TEMP_BUFFER;
    char szSymPath[nSymPathLen];
    szSymPath[0] = 0;

    if ((this->m_options & SymBuildPath) != 0) {
        // Now first add the (optional) provided sympath:
        if (this->m_szSymPath[0] != 0) {
            strcat_s (szSymPath, nSymPathLen, this->m_szSymPath);
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

        if ((this->m_options & SymUseSymSrv) != 0) {
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
    BOOL bRet = this->m_sw->Init (szSymPath);

    if (bRet == FALSE) {
        this->OnDbgHelpErr ("Error while initializing dbghelp.dll", 0, 0);
        SetLastError (ERROR_DLL_INIT_FAILED);
        return FALSE;
    }

    bRet = this->m_sw->LoadModules (this->m_hProcess, this->m_dwProcessId);
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
    static const size_t BUFFER_LEN = StackWalker::STACKWALK_MAX_NAMELEN;
    char buffer[BUFFER_LEN];
};

BOOL StackWalker::ShowCallstack (HANDLE hThread,
                                 const CONTEXT *context,
                                 PReadProcessMemoryRoutine readMemoryFunction,
                                 LPVOID pUserData) {
    CONTEXT c;
    CallstackEntry csEntry;
    IMAGEHLP_SYMBOL64_WITH_NAME sym;
    StackWalkerInternal::IMAGEHLP_MODULE64_V3 Module;
    IMAGEHLP_LINE64 Line;
    int frameNum;
    bool bLastEntryCalled = true;
    int curRecursionCount = 0;

    if (m_modulesLoaded == FALSE)
        this->LoadModules (); // ignore the result...

    if (this->m_sw->m_hDbhHelp == NULL) {
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
	this->m_sw->ArchSetup(c, s, imageType);


    memset (&sym, 0, sizeof (IMAGEHLP_SYMBOL64_WITH_NAME));
    sym.SizeOfStruct = sizeof (IMAGEHLP_SYMBOL64);
    sym.MaxNameLength = STACKWALK_MAX_NAMELEN;

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
        if (!this->m_sw->pSW (imageType, this->m_hProcess, hThread, &s, &c, myReadProcMem,
                              this->m_sw->pSFTA, this->m_sw->pSGMB, NULL)) {
            // INFO: "StackWalk64" does not set "GetLastError"...
            this->OnDbgHelpErr ("StackWalk64", 0, s.AddrPC.Offset);
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
            if ((this->m_MaxRecursionCount > 0) && (curRecursionCount > m_MaxRecursionCount)) {
                this->OnDbgHelpErr ("StackWalk64-Endless-Callstack!", 0, s.AddrPC.Offset);
                break;
            }
            curRecursionCount++;
        } else
            curRecursionCount = 0;
        if ((m_options & RetrieveSymbol) && s.AddrPC.Offset != 0) {
            // we seem to have a valid PC
            // show procedure info (SymGetSymFromAddr64())
            if (this->m_sw->pSGSFA (this->m_hProcess, s.AddrPC.Offset, &(csEntry.offsetFromSmybol), &sym) != FALSE) {
                MyStrCpy (csEntry.name, STACKWALK_MAX_NAMELEN, sym.Name);
                // UnDecorateSymbolName()
                this->m_sw->pUDSN (sym.Name, csEntry.undName, STACKWALK_MAX_NAMELEN, UNDNAME_NAME_ONLY);
                this->m_sw->pUDSN (sym.Name, csEntry.undFullName, STACKWALK_MAX_NAMELEN, UNDNAME_COMPLETE);
            } else {
                this->OnDbgHelpErr ("SymGetSymFromAddr64", GetLastError (), s.AddrPC.Offset);
            }

            // show line number info, NT5.0-method (SymGetLineFromAddr64())
            if ( (m_options & RetrieveLineAndFile) && this->m_sw->pSGLFA != NULL) { // yes, we have SymGetLineFromAddr64()
                if (this->m_sw->pSGLFA (this->m_hProcess, s.AddrPC.Offset,
                                        &(csEntry.offsetFromLine), &Line) != FALSE) {
                    csEntry.lineNumber = Line.LineNumber;
                    MyStrCpy (csEntry.lineFileName, STACKWALK_MAX_NAMELEN, Line.FileName);
                } else {
                    this->OnDbgHelpErr ("SymGetLineFromAddr64", GetLastError (), s.AddrPC.Offset);
                }
            } // yes, we have SymGetLineFromAddr64()

            // show module info (SymGetModuleInfo64())
			if ((m_options & RetrieveModuleInfo))
			{
				if (this->m_sw->GetModuleInfo(this->m_hProcess, s.AddrPC.Offset, &Module) != FALSE) { // got module info OK
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

					MyStrCpy(csEntry.moduleName, STACKWALK_MAX_NAMELEN, Module.ModuleName);
					csEntry.baseOfImage = Module.BaseOfImage;
					MyStrCpy(csEntry.loadedImageName, STACKWALK_MAX_NAMELEN, Module.LoadedImageName);
				} // got module info OK
				else {
					this->OnDbgHelpErr("SymGetModuleInfo64", GetLastError(), s.AddrPC.Offset);
				}
			}
        } // we seem to have a valid PC

        CallstackEntryType et = nextEntry;
        if (frameNum == 0)
            et = firstEntry;
        bLastEntryCalled = false;
        this->OnCallstackEntry (et, csEntry);

        if (s.AddrReturn.Offset == 0) {
            bLastEntryCalled = true;
            this->OnCallstackEntry (lastEntry, csEntry);
            SetLastError (ERROR_SUCCESS);
            break;
        }
    } // for ( frameNum )

    if (bLastEntryCalled == false)
        this->OnCallstackEntry (lastEntry, csEntry);

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
    CHAR buffer[STACKWALK_MAX_NAMELEN];
    if (fileVersion == 0)
        _snprintf_s (buffer, STACKWALK_MAX_NAMELEN, "%s:%s (%p), size: %d (result: %d), SymType: '%s', PDB: '%s'\n",
                     img, mod, (LPVOID)baseAddr, size, result, symType, pdbName);
    else {
        DWORD v4 = (DWORD) (fileVersion & 0xFFFF);
        DWORD v3 = (DWORD) ((fileVersion >> 16) & 0xFFFF);
        DWORD v2 = (DWORD) ((fileVersion >> 32) & 0xFFFF);
        DWORD v1 = (DWORD) ((fileVersion >> 48) & 0xFFFF);
        _snprintf_s (buffer, STACKWALK_MAX_NAMELEN,
                     "%s:%s (%p), size: %d (result: %d), SymType: '%s', PDB: '%s', "
                     "fileVersion: %d.%d.%d.%d\n",
                     img, mod, (LPVOID)baseAddr, size, result, symType, pdbName, v1, v2, v3, v4);
    }
    OnOutput (buffer);
}

void StackWalker::OnCallstackEntry (CallstackEntryType eType, CallstackEntry &entry) {
    CHAR buffer[STACKWALK_MAX_NAMELEN];
    if ((eType != lastEntry) && (entry.offset != 0)) {
        if (entry.name[0] == 0)
            MyStrCpy (entry.name, STACKWALK_MAX_NAMELEN, "(function-name not available)");
        if (entry.undName[0] != 0)
            MyStrCpy (entry.name, STACKWALK_MAX_NAMELEN, entry.undName);
        if (entry.undFullName[0] != 0)
            MyStrCpy (entry.name, STACKWALK_MAX_NAMELEN, entry.undFullName);
        if (entry.lineFileName[0] == 0) {
            MyStrCpy (entry.lineFileName, STACKWALK_MAX_NAMELEN, "(filename not available)");
            if (entry.moduleName[0] == 0)
                MyStrCpy (entry.moduleName, STACKWALK_MAX_NAMELEN, "(module-name not available)");
            _snprintf_s (buffer, STACKWALK_MAX_NAMELEN, "%p (%s): %s: %s\n", (LPVOID)entry.offset,
                         entry.moduleName, entry.lineFileName, entry.name);
        } else
            _snprintf_s (buffer, STACKWALK_MAX_NAMELEN, "%s (%d): %s\n", entry.lineFileName,
                         entry.lineNumber, entry.name);
        buffer[STACKWALK_MAX_NAMELEN - 1] = 0;
        OnOutput (buffer);
    }
}

void StackWalker::OnDbgHelpErr (LPCSTR szFuncName, DWORD gle, DWORD64 addr) {
    CHAR buffer[STACKWALK_MAX_NAMELEN];
    _snprintf_s (buffer, STACKWALK_MAX_NAMELEN, "ERROR: %s, GetLastError: %d (Address: %p)\n",
                 szFuncName, gle, (LPVOID)addr);
    OnOutput (buffer);
}

void StackWalker::OnSymInit (LPCSTR szSearchPath, DWORD symOptions, LPCSTR szUserName) {
    CHAR buffer[STACKWALK_MAX_NAMELEN];
    _snprintf_s (buffer, STACKWALK_MAX_NAMELEN, "SymInit: Symbol-SearchPath: '%s', symOptions: %d, UserName: '%s'\n",
                 szSearchPath, symOptions, szUserName);
    OnOutput (buffer);
// Also display the OS-version
#if _MSC_VER <= 1200
    OSVERSIONINFOA ver;
    ZeroMemory (&ver, sizeof (OSVERSIONINFOA));
    ver.dwOSVersionInfoSize = sizeof (ver);
    if (GetVersionExA (&ver) != FALSE) {
        _snprintf_s (buffer, STACKWALK_MAX_NAMELEN, "OS-Version: %d.%d.%d (%s)\n",
                     ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber, ver.szCSDVersion);
        OnOutput (buffer);
    }
#else
    OSVERSIONINFOEXA ver;
    ZeroMemory (&ver, sizeof (OSVERSIONINFOEXA));
    ver.dwOSVersionInfoSize = sizeof (ver);
    if (GetVersionExA ((OSVERSIONINFOA *)&ver) != FALSE) {
        _snprintf_s (buffer, STACKWALK_MAX_NAMELEN, "OS-Version: %d.%d.%d (%s) 0x%x-0x%x\n",
                     ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber, ver.szCSDVersion,
                     ver.wSuiteMask, ver.wProductType);
        OnOutput (buffer);
    }
#endif
}

void StackWalker::OnOutput (LPCSTR buffer) {
    OutputDebugStringA (buffer);
}
