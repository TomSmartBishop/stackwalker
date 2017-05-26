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



class StackWalker;

class StackWalkerInternal {
public:

#pragma pack(push, 8)
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

private:
	// **************************************** ToolHelp32 ************************
#define MAX_MODULE_NAME32 255
#define TH32CS_SNAPMODULE 0x00000008
#pragma pack(push, 8)
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
#pragma pack(pop)

	BOOL GetModuleListTH32(HANDLE hProcess, DWORD pid);

	  // **************************************** PSAPI ************************
	typedef struct _MODULEINFO {
		LPVOID lpBaseOfDll;
		DWORD SizeOfImage;
		LPVOID EntryPoint;
	} MODULEINFO, *LPMODULEINFO;

	BOOL GetModuleListPSAPI(HANDLE hProcess);

	DWORD LoadModule(HANDLE hProcess, LPCSTR img, LPCSTR mod, DWORD64 baseAddr, DWORD size);

	static const wchar_t * StackWalkerInternal::dbg_help_path[];

public:

	StackWalkerInternal(StackWalker *parent, HANDLE hProcess);

	~StackWalkerInternal();

	BOOL Init(LPCSTR szSymPath);

	BOOL LoadModules(HANDLE hProcess, DWORD dwProcessId);

	BOOL GetModuleInfo(HANDLE hProcess, DWORD64 baseAddr, IMAGEHLP_MODULE64_V3 *pModuleInfo);

	void ArchSetup(const CONTEXT &c, STACKFRAME64 &s, DWORD &imageType);

	StackWalker *m_parent;

	HMODULE m_hDbhHelp;
	HANDLE m_hProcess;
	CHAR m_szSymPath[4096/*StackWalker::STACKWALK_MAX_TEMP_BUFFER*/];

};
