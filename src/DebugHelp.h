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
#pragma once

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

#define MAX_MODULE_NAME32 255
#define TH32CS_SNAPMODULE 0x00000008

// If VC7 and later, then use the shipped 'dbghelp.h'-file
#pragma pack(push, 8)
#if _MSC_VER >= 1300

#pragma warning(push)
#pragma warning(disable : 4091) // warning C4091: 'typedef ': ignored on left of
// '' when no variable is declared

#include <dbghelp.h>

#pragma warning(pop)

#else
// inline the important dbghelp.h-declarations...
typedef enum {
	SymNone = 0,
	SymCoff,
	SymCv,
	SymPdb,
	SymExport,
	SymDeferred,
	SymSym,
	SymDia,
	SymVirtual,
	NumSymTypes
} SYM_TYPE;
typedef struct _IMAGEHLP_LINE64 {
	DWORD SizeOfStruct; // set to sizeof(IMAGEHLP_LINE64)
	PVOID Key;          // internal
	DWORD LineNumber;   // line number in file
	PCHAR FileName;     // full filename
	DWORD64 Address;    // first instruction of line
} IMAGEHLP_LINE64, *PIMAGEHLP_LINE64;
typedef struct _IMAGEHLP_MODULE64 {
	DWORD SizeOfStruct;        // set to sizeof(IMAGEHLP_MODULE64)
	DWORD64 BaseOfImage;       // base load address of module
	DWORD ImageSize;           // virtual size of the loaded module
	DWORD TimeDateStamp;       // date/time stamp from pe header
	DWORD CheckSum;            // checksum from the pe header
	DWORD NumSyms;             // number of symbols in the symbol table
	SYM_TYPE SymType;          // type of symbols loaded
	CHAR ModuleName[32];       // module name
	CHAR ImageName[256];       // image name
	CHAR LoadedImageName[256]; // symbol file name
} IMAGEHLP_MODULE64, *PIMAGEHLP_MODULE64;
typedef struct _IMAGEHLP_SYMBOL64 {
	DWORD SizeOfStruct;  // set to sizeof(IMAGEHLP_SYMBOL64)
	DWORD64 Address;     // virtual address including dll base address
	DWORD Size;          // estimated size of symbol, can be zero
	DWORD Flags;         // info about the symbols, see the SYMF defines
	DWORD MaxNameLength; // maximum size of symbol name in 'Name'
	CHAR Name[1];        // symbol name (null terminated string)
} IMAGEHLP_SYMBOL64, *PIMAGEHLP_SYMBOL64;
typedef enum { AddrMode1616, AddrMode1632, AddrModeReal, AddrModeFlat } ADDRESS_MODE;
typedef struct _tagADDRESS64 {
	DWORD64 Offset;
	WORD Segment;
	ADDRESS_MODE Mode;
} ADDRESS64, *LPADDRESS64;
typedef struct _KDHELP64 {
	DWORD64 Thread;
	DWORD ThCallbackStack;
	DWORD ThCallbackBStore;
	DWORD NextCallback;
	DWORD FramePointer;
	DWORD64 KiCallUserMode;
	DWORD64 KeUserCallbackDispatcher;
	DWORD64 SystemRangeStart;
	DWORD64 Reserved[8];
} KDHELP64, *PKDHELP64;
typedef struct _tagSTACKFRAME64 {
	ADDRESS64 AddrPC;     // program counter
	ADDRESS64 AddrReturn; // return address
	ADDRESS64 AddrFrame;  // frame pointer
	ADDRESS64 AddrStack;  // stack pointer
	ADDRESS64 AddrBStore; // backing store pointer
	PVOID FuncTableEntry; // pointer to pdata/fpo or NULL
	DWORD64 Params[4];    // possible arguments to the function
	BOOL Far;             // WOW far call
	BOOL Virtual;         // is this a virtual frame?
	DWORD64 Reserved[3];
	KDHELP64 KdHelp;
} STACKFRAME64, *LPSTACKFRAME64;
typedef BOOL(__stdcall *PREAD_PROCESS_MEMORY_ROUTINE64) (HANDLE hProcess,
	DWORD64 qwBaseAddress,
	PVOID lpBuffer,
	DWORD nSize,
	LPDWORD lpNumberOfBytesRead);
typedef PVOID(__stdcall *PFUNCTION_TABLE_ACCESS_ROUTINE64) (HANDLE hProcess, DWORD64 AddrBase);
typedef DWORD64(__stdcall *PGET_MODULE_BASE_ROUTINE64) (HANDLE hProcess, DWORD64 Address);
typedef DWORD64(__stdcall *PTRANSLATE_ADDRESS_ROUTINE64) (HANDLE hProcess, HANDLE hThread, LPADDRESS64 lpaddr);
#define SYMOPT_CASE_INSENSITIVE 0x00000001
#define SYMOPT_UNDNAME 0x00000002
#define SYMOPT_DEFERRED_LOADS 0x00000004
#define SYMOPT_NO_CPP 0x00000008
#define SYMOPT_LOAD_LINES 0x00000010
#define SYMOPT_OMAP_FIND_NEAREST 0x00000020
#define SYMOPT_LOAD_ANYTHING 0x00000040
#define SYMOPT_IGNORE_CVREC 0x00000080
#define SYMOPT_NO_UNQUALIFIED_LOADS 0x00000100
#define SYMOPT_FAIL_CRITICAL_ERRORS 0x00000200
#define SYMOPT_EXACT_SYMBOLS 0x00000400
#define SYMOPT_ALLOW_ABSOLUTE_SYMBOLS 0x00000800
#define SYMOPT_IGNORE_NT_SYMPATH 0x00001000
#define SYMOPT_INCLUDE_32BIT_MODULES 0x00002000
#define SYMOPT_PUBLICS_ONLY 0x00004000
#define SYMOPT_NO_PUBLICS 0x00008000
#define SYMOPT_AUTO_PUBLICS 0x00010000
#define SYMOPT_NO_IMAGE_SEARCH 0x00020000
#define SYMOPT_SECURE 0x00040000
#define SYMOPT_DEBUG 0x80000000
#define UNDNAME_COMPLETE (0x0000)  // Enable full un-decoration
#define UNDNAME_NAME_ONLY (0x1000) // Crack only the name for primary declaration;

#endif                             // _MSC_VER < 1300

typedef struct tagMODULEENTRY32 {
	DWORD dwSize;
	DWORD th32ModuleID;  // This module
	DWORD th32ProcessID; // owning process
	DWORD GlblcntUsage;  // Global usage count on the module
	DWORD ProccntUsage;  // Module usage count in th32ProcessID's context
	BYTE *modBaseAddr;   // Base address of module in th32ProcessID's context
	DWORD modBaseSize;   // Size in bytes of module starting at modBaseAddr
	HMODULE
		hModule; // The hModule of this module in th32ProcessID's context
	char szModule[MAX_MODULE_NAME32 + 1];
	char szExePath[MAX_PATH];
} MODULEENTRY32;
typedef MODULEENTRY32 *PMODULEENTRY32;
typedef MODULEENTRY32 *LPMODULEENTRY32;

struct IMAGEHLP_MODULE64_V3 {
	DWORD SizeOfStruct;        // set to sizeof(IMAGEHLP_MODULE64)
	DWORD64 BaseOfImage;       // base load address of module
	DWORD ImageSize;           // virtual size of the loaded module
	DWORD TimeDateStamp;       // date/time stamp from pe header
	DWORD CheckSum;            // checksum from the pe header
	DWORD NumSyms;             // number of symbols in the symbol table
	SYM_TYPE SymType;          // type of symbols loaded
	CHAR ModuleName[32];       // module name
	CHAR ImageName[256];       // image name
	CHAR LoadedImageName[256]; // symbol file name
							   // new elements: 07-Jun-2002
	CHAR LoadedPdbName[256];   // pdb file name
	DWORD CVSig;               // Signature of the CV record in the debug directories
	CHAR CVData[MAX_PATH * 3]; // Contents of the CV record
	DWORD PdbSig;              // Signature of PDB
	GUID PdbSig70;             // Signature of PDB (VC 7 and up)
	DWORD PdbAge;              // DBI age of pdb
	BOOL PdbUnmatched;         // loaded an unmatched pdb
	BOOL DbgUnmatched;         // loaded an unmatched dbg
	BOOL LineNumbers;          // we have line number information
	BOOL GlobalSymbols;        // we have internal symbol information
	BOOL TypeInfo;             // we have type information
							   // new elements: 17-Dec-2003
	BOOL SourceIndexed; // pdb supports source server
	BOOL Publics;       // contains public symbols
};

struct IMAGEHLP_MODULE64_V2 {
	DWORD SizeOfStruct;        // set to sizeof(IMAGEHLP_MODULE64)
	DWORD64 BaseOfImage;       // base load address of module
	DWORD ImageSize;           // virtual size of the loaded module
	DWORD TimeDateStamp;       // date/time stamp from pe header
	DWORD CheckSum;            // checksum from the pe header
	DWORD NumSyms;             // number of symbols in the symbol table
	SYM_TYPE SymType;          // type of symbols loaded
	CHAR ModuleName[32];       // module name
	CHAR ImageName[256];       // image name
	CHAR LoadedImageName[256]; // symbol file name
};
#pragma pack(pop)