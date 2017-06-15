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

void OutputStackWalker::OnLoadModule (LPCSTR img,
                                      LPCSTR mod,
                                      DWORD64 baseAddr,
                                      DWORD size,
                                      DWORD result,
                                      LPCSTR symType,
                                      LPCSTR pdbName,
                                      ULONGLONG fileVersion) {
    CHAR buffer[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
    if (fileVersion == 0)
        _snprintf_s (buffer, Parameter::STACKWALKER_MAX_TEMP_BUFFER,
                     "%s:%s (%p), size: %d (result: %d), SymType: '%s', PDB: '%s'\n", img, mod,
                     (LPVOID)baseAddr, size, result, symType, pdbName);
    else {
        DWORD v4 = (DWORD) (fileVersion & 0xFFFF);
        DWORD v3 = (DWORD) ((fileVersion >> 16) & 0xFFFF);
        DWORD v2 = (DWORD) ((fileVersion >> 32) & 0xFFFF);
        DWORD v1 = (DWORD) ((fileVersion >> 48) & 0xFFFF);
        _snprintf_s (buffer, Parameter::STACKWALKER_MAX_TEMP_BUFFER,
                     "%s:%s (%p), size: %d (result: %d), SymType: '%s', PDB: '%s', "
                     "fileVersion: %d.%d.%d.%d\n",
                     img, mod, (LPVOID)baseAddr, size, result, symType, pdbName, v1, v2, v3, v4);
    }
    OnOutput (buffer);
}
static bool notEmpty(const CHAR * str)
{
	return str != NULL && str[0] != 0;
}
void OutputStackWalker::OnCallstackEntry (int frameNum, CallstackEntry &entry) {
    
    if (entry.offset != 0) {
		CHAR buffer[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
			
		const CHAR* lineFileName = notEmpty(entry.lineFileName) ? entry.lineFileName : "<no filename>";
		const CHAR* moduleName = notEmpty(entry.moduleName) ? entry.moduleName: "<no module name>";
		const CHAR* name = notEmpty(entry.undName) ? entry.undName : (notEmpty(entry.name) ? entry.name : "<no function name>");

        _snprintf_s (buffer, Parameter::STACKWALKER_MAX_TEMP_BUFFER, "[%s] 0x%p %s (%d): %s\n",
			moduleName, (LPVOID)entry.offset, lineFileName, entry.lineNumber, name);

        OnOutput (buffer);
    }
}

void OutputStackWalker::OnDbgHelpErr (LPCSTR szFuncName, DWORD gle, DWORD64 addr) {
    CHAR buffer[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
    _snprintf_s (buffer, Parameter::STACKWALKER_MAX_TEMP_BUFFER,
                 "ERROR: %s, GetLastError: %d (Address: %p)\n", szFuncName, gle, (LPVOID)addr);
    OnOutput (buffer);
}

void OutputStackWalker::OnSymbolInfo (LPCSTR szSearchPath, DWORD symOptions) {

    CHAR szUserName[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
    DWORD dwSize = Parameter::STACKWALKER_MAX_TEMP_BUFFER;
    GetUserNameA (szUserName, &dwSize);

    CHAR buffer[Parameter::STACKWALKER_MAX_TEMP_BUFFER];
    _snprintf_s (buffer, Parameter::STACKWALKER_MAX_TEMP_BUFFER,
                 "SymInit: Symbol-SearchPath: '%s', symOptions: %d, UserName: '%s'\n", szSearchPath,
                 symOptions, szUserName);
    OnOutput (buffer);
// Also display the OS-version
#if _MSC_VER <= 1200
    OSVERSIONINFOA ver;
    ZeroMemory (&ver, sizeof (OSVERSIONINFOA));
    ver.dwOSVersionInfoSize = sizeof (ver);
    if (GetVersionExA (&ver) != FALSE) {
        _snprintf_s (buffer, Parameter::STACKWALKER_MAX_TEMP_BUFFER, "OS-Version: %d.%d.%d (%s)\n",
                     ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber, ver.szCSDVersion);
        OnOutput (buffer);
    }
#else
    OSVERSIONINFOEXA ver;
    ZeroMemory (&ver, sizeof (OSVERSIONINFOEXA));
    ver.dwOSVersionInfoSize = sizeof (ver);
    if (GetVersionExA ((OSVERSIONINFOA *)&ver) != FALSE) {
        _snprintf_s (buffer, Parameter::STACKWALKER_MAX_TEMP_BUFFER,
                     "OS-Version: %d.%d.%d (%s) 0x%x-0x%x\n", ver.dwMajorVersion, ver.dwMinorVersion,
                     ver.dwBuildNumber, ver.szCSDVersion, ver.wSuiteMask, ver.wProductType);
        OnOutput (buffer);
    }
#endif
}

void OutputStackWalker::OnOutput (LPCSTR buffer) {
    OutputDebugStringA (buffer);
}
