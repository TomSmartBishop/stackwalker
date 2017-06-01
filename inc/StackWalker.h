/**********************************************************************
 *
 * StackWalker.h
 *
 *
 *
 * LICENSE (http://www.opensource.org/licenses/bsd-license.php)
 *
 *   Copyright (c) 2005-2009, Jochen Kalmbach
 *   All rights reserved.
 *
 * **********************************************************************/
// #pragma once is supported starting with _MCS_VER 1000,
// so we need not to check the version (because we only support _MSC_VER >=
// 1100)!
#pragma once


#pragma comment(lib, "version.lib") // for "VerQueryValue"
#pragma warning(push)
#pragma warning(disable : 4826)


// special defines for VC5/6 (if no actual PSDK is installed):
#if _MSC_VER < 1300
typedef unsigned __int64 DWORD64, *PDWORD64;
#if defined(_WIN64)
typedef unsigned __int64 SIZE_T, *PSIZE_T;
#else
typedef unsigned long SIZE_T, *PSIZE_T;
#endif
#endif // _MSC_VER < 1300

struct Parameter {
    enum StackWalkerParameter {
        STACKWALKER_MAX_NAMELEN = 1024,
        STACKWALKER_MAX_TEMP_BUFFER = 1024,
        STACKWALKER_INTERNAL_STRUCT_SIZE = 512
    }; // max name length for found symbols
};

class StackWalker {
    public:
    typedef enum StackWalkOptions {


        RetrieveNone = 0x0000, // No addition info will be retrieved (only the address is available)
        RetrieveSymbol = 0x0001, // Try to get the symbol-name
		RetrieveUndecoratedNames = 0x0002,
        RetrieveLineAndFile = 0x0004, // Try to get the line for this symbol (needs symbol information)
        RetrieveModuleInfo = 0x0008, // Try to retrieve the module-infos
        RetrieveFileVersion = 0x0010, // Also retrieve the version for the DLL/EXE (will allocate dynamic memory)
        RetrieveSymbolInfo = 0x0020, // Get the symbol flags and the symbol search path
        
        LoadModulesOnInit = 0x0100, // Load the modules when initializing STackwalker instead of the first ShowCallSTack
        SymBuildPath = 0x1000, // Generate a "good" symbol-search-path
        SymUseSymSrv = 0x2000, // Also use the public Microsoft-Symbol-Server
        SymAll = 0x3000,       // Contains all the above "Sym"-options
        
		OptionsSlim = 0x0105,
		OptionsAll = 0xFFFF    // Contains all options (default)

    } StackWalkOptions;


    StackWalker (DWORD dwProcessId, HANDLE hProcess);

    StackWalker (int options = OptionsAll,
                 int maxStepDepth = 0,
                 DWORD dwProcessId = GetCurrentProcessId (),
                 HANDLE hProcess = GetCurrentProcess ());

    StackWalker (int options,
                 int maxStepDepth,
                 LPCSTR szSymPath,
                 DWORD dwProcessId = GetCurrentProcessId (),
                 HANDLE hProcess = GetCurrentProcess ());


    virtual ~StackWalker ();

    typedef BOOL (__stdcall *PReadProcessMemoryRoutine) (
    HANDLE hProcess,
    DWORD64 qwBaseAddress,
    PVOID lpBuffer,
    DWORD nSize,
    LPDWORD lpNumberOfBytesRead,
    LPVOID pUserData // optional data, which was passed in "ShowCallstack"
    );

    BOOL LoadModules (LPCSTR szSymPath = NULL);

    BOOL ShowCallstack (HANDLE hThread = GetCurrentThread (),
                        const CONTEXT *context = NULL,
                        PReadProcessMemoryRoutine readMemoryFunction = NULL,
                        LPVOID pUserData = NULL // optional to identify some data
                                                // in the
                                                // 'readMemoryFunction'-callback
    );

    protected:
    // Entry for each Callstack-Entry
    typedef struct CallstackEntry {
        DWORD64 offset; // if 0, we have no valid entry
        CHAR name[Parameter::STACKWALKER_MAX_NAMELEN];
        CHAR undName[Parameter::STACKWALKER_MAX_NAMELEN];
        CHAR undFullName[Parameter::STACKWALKER_MAX_NAMELEN];
        DWORD64 offsetFromSmybol;
        DWORD offsetFromLine;
        DWORD lineNumber;
        CHAR lineFileName[Parameter::STACKWALKER_MAX_NAMELEN];
        DWORD symType;
        LPCSTR symTypeString;
        CHAR moduleName[Parameter::STACKWALKER_MAX_NAMELEN];
        DWORD64 baseOfImage;
        CHAR loadedImageName[Parameter::STACKWALKER_MAX_NAMELEN];
    } CallstackEntry;

    enum CallstackEntryType { firstEntry, nextEntry, lastEntry };


    virtual void OnLoadModule (LPCSTR img,
                               LPCSTR mod,
                               DWORD64 baseAddr,
                               DWORD size,
                               DWORD result,
                               LPCSTR symType,
                               LPCSTR pdbName,
                               ULONGLONG fileVersion) = 0;
    virtual void OnCallstackEntry (CallstackEntryType eType, CallstackEntry &entry) = 0;
    virtual void OnSymbolInfo (LPCSTR szSearchPath, DWORD symOptions) = 0;
    virtual void OnDbgHelpErr (LPCSTR szFuncName, DWORD gle, DWORD64 addr) = 0;


    HANDLE m_hProcess;
    DWORD m_dwProcessId;
    BOOL m_modulesLoaded;
    CHAR m_szSymPath[Parameter::STACKWALKER_MAX_TEMP_BUFFER];

    int m_options;
    int m_MaxRecursionCount;
    int m_MaxStackDepth;


    static void StrCpy (char *szDest, size_t nMaxDestSize, const char *szSrc);
    static BOOL __stdcall myReadProcMem (HANDLE hProcess, DWORD64 qwBaseAddress, PVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead);


    private:
    struct Internal;

    Internal &internal () {
        return reinterpret_cast<Internal &> (m_storage);
    }
    Internal const &internal () const {
        return reinterpret_cast<Internal const &> (m_storage);
    }

    char m_storage[Parameter::STACKWALKER_INTERNAL_STRUCT_SIZE];

}; // class StackWalker

class OutputStackWalker : public StackWalker {

    public:
    OutputStackWalker::OutputStackWalker (DWORD dwProcessId, HANDLE hProcess)
    : StackWalker (dwProcessId, hProcess) {
    }

    OutputStackWalker::OutputStackWalker (int options = OptionsAll,
                                          int maxStackDepth = 0,
                                          DWORD dwProcessId = GetCurrentProcessId (),
                                          HANDLE hProcess = GetCurrentProcess ())
    : StackWalker (options, maxStackDepth, dwProcessId, hProcess) {
    }

    OutputStackWalker::OutputStackWalker (int options,
                                          int maxStackDepth,
                                          LPCSTR szSymPath,
                                          DWORD dwProcessId = GetCurrentProcessId (),
                                          HANDLE hProcess = GetCurrentProcess ())
    : StackWalker (options, maxStackDepth, szSymPath, dwProcessId, hProcess) {
    }

    protected:
    virtual void
    OnLoadModule (LPCSTR img, LPCSTR mod, DWORD64 baseAddr, DWORD size, DWORD result, LPCSTR symType, LPCSTR pdbName, ULONGLONG fileVersion);
    virtual void OnCallstackEntry (CallstackEntryType eType, CallstackEntry &entry);
    virtual void OnSymbolInfo (LPCSTR szSearchPath, DWORD symOptions);
    virtual void OnDbgHelpErr (LPCSTR szFuncName, DWORD gle, DWORD64 addr);
    virtual void OnOutput (LPCSTR szText);
};

#pragma warning(pop)
