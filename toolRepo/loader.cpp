#include <windows.h>
#include <stdio.h>

typedef struct _PE_LOADER_CONTEXT {
	LPVOID baseAddress;
	LPVOID entryPoint;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeaders;
	PIMAGE_SECTION_HEADER sectionHeaders;
	DWORD imageSize;

} PE_LOADER_CONTEXT, * PPE_LOADER_CONTEXT;



BOOL ValidatePE(LPVOID peBytes, PPE_LOADER_CONTEXT ctx);
BOOL AllocateMemoryForPE(LPVOID peBytes, PPE_LOADER_CONTEXT ctx);
BOOL CopySections(LPVOID peBytes, PPE_LOADER_CONTEXT ctx);
BOOL ProcessRelocations(PPE_LOADER_CONTEXT ctx);
BOOL ResolveImports(PPE_LOADER_CONTEXT ctx);
BOOL SetMemoryProtections(PPE_LOADER_CONTEXT ctx);
BOOL ExecutePE(PPE_LOADER_CONTEXT ctx);


BOOL ValidatePE(LPVOID peBytes, PPE_LOADER_CONTEXT ctx) {
	printf("Validating PE file...\n");

	if (peBytes == NULL) {
		printf("PE bytes is NULL.\n");
		return FALSE;
	}

	ctx->dosHeader = (PIMAGE_DOS_HEADER)peBytes;
	ctx->ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)peBytes + ctx->dosHeader->e_lfanew);

	if (ctx->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature.\n");
		return FALSE;
	}
	if (ctx->ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT signature.\n");
		return FALSE;
	}

	if (ctx->ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		printf("PE file is x64 (64-bit).\n");
	}
	else if (ctx->ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		printf("PE file is x86 (32-bit).\n");
	}
	else {
		printf("Unknown machine type: 0x%X\n", ctx->ntHeaders->FileHeader.Machine);
		return FALSE;
	}

	if (ctx->ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		printf("PE file is a DLL.\n");
	}
	else {
		printf("PE file is an executable.\n");
	}
	return TRUE;
}


BOOL AllocateMemoryForPE(LPVOID peBytes, PPE_LOADER_CONTEXT ctx) {
	printf("Allocating memory for PE...\n");
	ctx->imageSize = ctx->ntHeaders->OptionalHeader.SizeOfImage;
	ctx->baseAddress = VirtualAlloc(
		NULL,
		ctx->imageSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);
	if (ctx->baseAddress == NULL) {
		printf("Failed to allocate memory! Error: %d\n", GetLastError());
		return FALSE;
	}
	printf("Allocated size: 0x%X bytes\n", ctx->imageSize);
	return TRUE;
}



BOOL CopySections(LPVOID peBytes, PPE_LOADER_CONTEXT ctx) {
	printf("Loading PE from memory...\n");
	DWORD headerSize = ctx->ntHeaders->OptionalHeader.SizeOfHeaders;
	memcpy(ctx->baseAddress, peBytes, headerSize);
	ctx->ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ctx->baseAddress +
		((PIMAGE_DOS_HEADER)ctx->baseAddress)->e_lfanew);

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ctx->ntHeaders);
	for (int i = 0; i < ctx->ntHeaders->FileHeader.NumberOfSections; i++) {
		memcpy((BYTE*)ctx->baseAddress + section[i].VirtualAddress,
			(BYTE*)peBytes + section[i].PointerToRawData,
			section[i].SizeOfRawData);
		printf("Section %s loaded successfully\n", section[i].Name);
	}

	return TRUE;
}


BOOL ProcessRelocations(PPE_LOADER_CONTEXT ctx) {
	printf("Process Relocations\n");
	LONGLONG delta = (LONGLONG)ctx->baseAddress - ctx->ntHeaders->OptionalHeader.ImageBase;
	printf("delta is: %lld bytes\n", delta);
	PIMAGE_DATA_DIRECTORY relocDir = &ctx->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocDir->Size == 0) {
		printf("No relocation data. PE must load at preferred ImageBase.\n");
		return TRUE;
	}
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)ctx->baseAddress + relocDir->VirtualAddress);
	int relocCount = 0;

	while (relocation->VirtualAddress != 0) {
		BYTE* dest = (BYTE*)ctx->baseAddress + relocation->VirtualAddress;
		DWORD numEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* relocEntry = (WORD*)(relocation + 1);
		for (DWORD i = 0; i < numEntries; i++) {
			WORD type = relocEntry[i] >> 12;
			WORD offset = relocEntry[i] & 0xFFF;
			if (type == IMAGE_REL_BASED_DIR64) {
				LONGLONG* patchAddr = (LONGLONG*)(dest + offset);
				*patchAddr += delta;
				relocCount++;
			}
			else if (type == IMAGE_REL_BASED_HIGHLOW) {
				DWORD* patchAddr = (DWORD*)(dest + offset);
				*patchAddr += (DWORD)delta;
				relocCount++;
			}
		}
		relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
	}
	printf("Applied %d relocations\n", relocCount);

	return TRUE;
}

BOOL ResolveImports(PPE_LOADER_CONTEXT ctx) {
	printf("Resolving imports\n");
	PIMAGE_DATA_DIRECTORY importDir = &ctx->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir->VirtualAddress == 0 || importDir->Size == 0) {
		printf("No imports directory present.\n");
		return TRUE;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)ctx->baseAddress + importDir->VirtualAddress);

	BOOL is64 =
		(ctx->ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
		(ctx->ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

	for (; importDesc->Name != 0; importDesc++) {
		char* dllName = (char*)((BYTE*)ctx->baseAddress + importDesc->Name);
		HMODULE hMod = LoadLibraryA(dllName);
		if (hMod == NULL) {
			printf("Failed to load DLL: %s (err=%lu)\n", dllName, GetLastError());
			return FALSE;
		}

		if (is64) {
			PIMAGE_THUNK_DATA64 thunkRef = NULL;
			PIMAGE_THUNK_DATA64 funcRef =
				(PIMAGE_THUNK_DATA64)((BYTE*)ctx->baseAddress + importDesc->FirstThunk);

			if (importDesc->OriginalFirstThunk) {
				thunkRef =
					(PIMAGE_THUNK_DATA64)((BYTE*)ctx->baseAddress + importDesc->OriginalFirstThunk);
			}
			else {
				thunkRef = funcRef;
			}

			for (; thunkRef->u1.AddressOfData != 0; thunkRef++, funcRef++) {
				FARPROC proc = NULL;

				if (thunkRef->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
					WORD ordinal = (WORD)(thunkRef->u1.Ordinal & 0xFFFF);
					proc = GetProcAddress(hMod, (LPCSTR)(ULONG_PTR)ordinal);
				}
				else {
					PIMAGE_IMPORT_BY_NAME importByName =
						(PIMAGE_IMPORT_BY_NAME)((BYTE*)ctx->baseAddress + thunkRef->u1.AddressOfData);
					proc = GetProcAddress(hMod, (LPCSTR)importByName->Name);
				}

				if (proc == NULL) {
					printf("Failed to resolve import from %s (err=%lu)\n", dllName, GetLastError());
					return FALSE;
				}

				funcRef->u1.Function = (ULONGLONG)(ULONG_PTR)proc;
			}
		}
		else {
			PIMAGE_THUNK_DATA32 thunkRef = NULL;
			PIMAGE_THUNK_DATA32 funcRef =
				(PIMAGE_THUNK_DATA32)((BYTE*)ctx->baseAddress + importDesc->FirstThunk);

			if (importDesc->OriginalFirstThunk) {
				thunkRef =
					(PIMAGE_THUNK_DATA32)((BYTE*)ctx->baseAddress + importDesc->OriginalFirstThunk);
			}
			else {
				thunkRef = funcRef;
			}

			for (; thunkRef->u1.AddressOfData != 0; thunkRef++, funcRef++) {
				FARPROC proc = NULL;

				if (thunkRef->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
					WORD ordinal = (WORD)(thunkRef->u1.Ordinal & 0xFFFF);
					proc = GetProcAddress(hMod, (LPCSTR)(ULONG_PTR)ordinal);
				}
				else {
					PIMAGE_IMPORT_BY_NAME importByName =
						(PIMAGE_IMPORT_BY_NAME)((BYTE*)ctx->baseAddress + thunkRef->u1.AddressOfData);
					proc = GetProcAddress(hMod, (LPCSTR)importByName->Name);
				}

				if (proc == NULL) {
					printf("Failed to resolve import from %s (err=%lu)\n", dllName, GetLastError());
					return FALSE;
				}

				funcRef->u1.Function = (DWORD)(ULONG_PTR)proc;
			}
		}

		printf("Resolved imports for %s\n", dllName);
	}

	return TRUE;
}

BOOL SetMemoryProtections(PPE_LOADER_CONTEXT ctx) {
	printf("Setting memory protections...\n");

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ctx->ntHeaders);
	WORD numberOfSections = ctx->ntHeaders->FileHeader.NumberOfSections;

	for (WORD i = 0; i < numberOfSections; i++) {
		DWORD protect = 0;
		DWORD characteristics = section[i].Characteristics;

		BOOL executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		BOOL readable   = (characteristics & IMAGE_SCN_MEM_READ) != 0;
		BOOL writable   = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

		if (!executable && !writable && readable) {
			protect = PAGE_READONLY;
		}
		else if (!executable && writable && readable) {
			protect = PAGE_READWRITE;
		}
		else if (executable && !writable && readable) {
			protect = PAGE_EXECUTE_READ;
		}
		else if (executable && writable && readable) {
			protect = PAGE_EXECUTE_READWRITE;
		}
		else if (executable && !writable && !readable) {
			protect = PAGE_EXECUTE;
		}
		else if (!executable && writable && !readable) {
			protect = PAGE_WRITECOPY;
		}
		else {
			protect = PAGE_NOACCESS;
		}

		LPVOID sectionAddress = (LPBYTE)ctx->baseAddress + section[i].VirtualAddress;
		SIZE_T sectionSize = section[i].Misc.VirtualSize;
		if (sectionSize == 0) {
			sectionSize = section[i].SizeOfRawData;
		}

		DWORD oldProtect = 0;
		if (!VirtualProtect(sectionAddress, sectionSize, protect, &oldProtect)) {
			printf("VirtualProtect failed for section %.*s (err=%lu)\n",
				IMAGE_SIZEOF_SHORT_NAME, section[i].Name, GetLastError());
			return FALSE;
		}
	}

	return TRUE;
}


BOOL ExecutePE(PPE_LOADER_CONTEXT ctx) {
	printf("Executing PE...\n");

	DWORD entryRva = ctx->ntHeaders->OptionalHeader.AddressOfEntryPoint;
	if (entryRva == 0) {
		printf("No entry point specified in PE.\n");
		return FALSE;
	}

	ctx->entryPoint = (LPBYTE)ctx->baseAddress + entryRva;

	if (ctx->ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE, DWORD, LPVOID);
		DllEntryProc dllEntry = (DllEntryProc)ctx->entryPoint;

		BOOL result = dllEntry((HINSTANCE)ctx->baseAddress, DLL_PROCESS_ATTACH, NULL);
		printf("DllMain returned %d\n", result);
		return result;
	}
	else {
		typedef int(*ExeEntryProc)();
		ExeEntryProc exeEntry = (ExeEntryProc)ctx->entryPoint;

		int ret = exeEntry();
		printf("Executable entry returned %d\n", ret);
		return TRUE;
	}
}


int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("Usage: %s <pe_file>\n", argv[0]);
		return 1;
	}

	FILE* file;
	fopen_s(&file, argv[1], "rb");
	if (file == NULL) {
		printf("Failed to open file: %s\n", argv[1]);
		return 1;
	}

	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	fseek(file, 0, SEEK_SET);

	LPVOID peBytes = malloc(fileSize);
	if (peBytes == NULL) {
		printf("Failed to allocate memory for file\n");
		fclose(file);
		return 1;
	}

	fread(peBytes, 1, fileSize, file);
	fclose(file);

	printf("Loaded %ld bytes from %s\n", fileSize, argv[1]);
	PE_LOADER_CONTEXT ctx = { 0 };

	// BUG FIX #4: Check return value of every stage — fail fast on any error
	if (!ValidatePE(peBytes, &ctx)) {
		printf("PE validation failed.\n");
		free(peBytes);
		return 1;
	}
	if (!AllocateMemoryForPE(peBytes, &ctx)) {
		printf("Memory allocation failed.\n");
		free(peBytes);
		return 1;
	}
	if (!CopySections(peBytes, &ctx)) {
		printf("CopySections failed.\n");
		free(peBytes);
		return 1;
	}
	if (!ProcessRelocations(&ctx)) {
		printf("ProcessRelocations failed.\n");
		free(peBytes);
		return 1;
	}
	if (!ResolveImports(&ctx)) {
		printf("ResolveImports failed.\n");
		free(peBytes);
		return 1;
	}
	if (!SetMemoryProtections(&ctx)) {
		printf("SetMemoryProtections failed.\n");
		free(peBytes);
		return 1;
	}

	free(peBytes);

	if (!ExecutePE(&ctx)) {
		printf("Execution of PE failed.\n");
		return 1;
	}

	return 0;
}