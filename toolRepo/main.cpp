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
	ctx->dosHeader = (PIMAGE_DOS_HEADER)peBytes;
	ctx->ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)peBytes + ctx->dosHeader->e_lfanew);
	printf("Validating PE file...\n");
	if (peBytes == NULL) {
		printf("PE bytes is NULL.\n");
		return FALSE;
	}

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
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ctx->ntHeaders); // points to the next byte after the NtHeader
	for (int i = 0; i < ctx->ntHeaders->FileHeader.NumberOfSections; i++) {
		memcpy((BYTE*)ctx->baseAddress + section[i].VirtualAddress,
			(BYTE*)peBytes + section[i].PointerToRawData,
			section[i].SizeOfRawData);
		printf("Section %s loaded secessfully \n", section[i].Name);

	}
	
	return TRUE;

}


BOOL ProccessRelocations(PPE_LOADER_CONTEXT ctx) {
	printf("Proccess Relocations \n");
	LONGLONG delta = (LONGLONG)ctx->baseAddress - ctx->ntHeaders->OptionalHeader.ImageBase;
	printf("delta is: %lld bytes \n", delta);
	PIMAGE_DATA_DIRECTORY relocDir = &ctx->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]; // DataDirectory[5]
	if (relocDir->Size == 0) {
		printf("No relocation datacPE cannot be loaded at different base \n");
		return FALSE;
	}
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)ctx->baseAddress + relocDir->VirtualAddress); // structs with header + entries (blocks to change)
	int relocCount = 0;

	while (relocation->VirtualAddress != 0) {
		
	}


	return TRUE;
}


int main(int argc, char* argv[]) 
{
	FILE* file;
	fopen_s(&file, argv[1], "rb");    if (file == NULL) {
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


	ValidatePE(peBytes, &ctx);
	AllocateMemoryForPE(peBytes, &ctx);
	CopySections(peBytes, &ctx);
	ProccessRelocations(&ctx);



    return 0;
}