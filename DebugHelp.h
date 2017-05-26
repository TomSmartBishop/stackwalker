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
#pragma once

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
#pragma pack(pop)