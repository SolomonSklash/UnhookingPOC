#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <iostream>
#include <fstream>
using namespace std;

void saveBytes(char bytes[], string filename, SIZE_T size)
{
	ofstream myfile;
	myfile.open(filename);

	for (int i = 0; i < size; i++)
	{
		myfile << bytes[i];
	}

	myfile.close();
	return;
}

int main()
{
	printf("[*] Getting a handle to the current process\n");
	HANDLE hCurrentProcess;
	try
	{
		hCurrentProcess = GetCurrentProcess();
	}
	catch (const std::exception&)
	{
		printf("[!] Failed to get handle to the current process!\n");
		exit(1);
	}
	/* MODULEINFO structure: Contains the module load address, size, and entry point
	typedef struct _MODULEINFO {
		LPVOID lpBaseOfDll;			// The load address of the module.
		DWORD  SizeOfImage;			// The size of the linear space that the module occupies, in bytes.
		LPVOID EntryPoint;			// The entry point of the module.
	} MODULEINFO, * LPMODULEINFO; */
	MODULEINFO miModuleInfo = {};

	// HMODULE GetModuleHandleA(LPCSTR lpModuleName) - Retrieves a module handle for the specified module. The module must have been loaded by the calling process (ntdll.dll always is).
	printf("[*] Getting a handle to the possibly hooked ntdll.dll module loaded in the current process\n");

	HMODULE hNtdllModule;
	try
	{
		hNtdllModule = GetModuleHandleA("ntdll.dll");
	}
	catch (const std::exception&)
	{
		printf("[!] Failed to get module handle to ntdll.dll!\n");
		exit(1);
	}

	/* GetModuleInformation() - Retrieves information about the specified module in the MODULEINFO structure.
	BOOL GetModuleInformation(
		HANDLE       hProcess,		// A handle to the process that contains the module.
		HMODULE      hModule,		// A handle to the module.
		LPMODULEINFO lpmodinfo,		// A pointer to the MODULEINFO structure that receives information about the module.
		DWORD        cb				// The size of the MODULEINFO structure, in bytes.
		); */
	printf("[*] Getting module information for the hooked ntdll.dll module\n");

	try
	{
		GetModuleInformation(hCurrentProcess, hNtdllModule, &miModuleInfo, sizeof(miModuleInfo));
	}
	catch (const std::exception&)
	{
		printf("[!] GetModuleInformation() failed!\n");
		exit(1);
	}

	// get a pointer to the base address of the hooked ntdll.dll module
	LPVOID pHookedNtdllBaseAddress = (LPVOID)miModuleInfo.lpBaseOfDll;

	/* getting a handle to the unhooked ntdll.dll file on disk
	HANDLE CreateFileA(
		LPCSTR                lpFileName,			// The name of the file or device to be created or opened.
		DWORD                 dwDesiredAccess,		// The requested access to the file or device, which can be summarized as read, write, both or neither zero).
		DWORD                 dwShareMode,			// The requested sharing mode of the file or device, which can be read, write, both, delete, all of these, or none.
		LPSECURITY_ATTRIBUTES lpSecurityAttributes, // A pointer to a SECURITY_ATTRIBUTES structure
		DWORD                 dwCreationDisposition,// An action to take on a file or device that exists or does not exist.
		DWORD                 dwFlagsAndAttributes,	// The file or device attributes and flags, FILE_ATTRIBUTE_NORMAL being the most common default value for files.
		HANDLE                hTemplateFile			// A valid handle to a template file with the GENERIC_READ access right. Can be NULL.
	);*/
	printf("[*] Getting a file handle for unhooked ntdll.dll on disk\n");

	HANDLE hNtdllFile;
	try
	{
		hNtdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	}
	catch (const std::exception&)
	{
		printf("[!] Failed getting file handle for ntdll.dll\n");
		exit(1);
	}

	/* Creates or opens a named or unnamed file mapping object for a specified file.
	HANDLE CreateFileMappingA(
		HANDLE                hFile,					// A handle to the file from which to create a file mapping object.
		LPSECURITY_ATTRIBUTES lpFileMappingAttributes,	// A pointer to a SECURITY_ATTRIBUTES structure that determines whether a returned handle can be inherited by child processes.
		DWORD                 flProtect,				// Specifies the page protection of the file mapping object. All mapped views of the object must be compatible with this protection.
		DWORD                 dwMaximumSizeHigh,		// The high-order DWORD of the maximum size of the file mapping object.
		DWORD                 dwMaximumSizeLow,			// The low-order DWORD of the maximum size of the file mapping object.
		LPCSTR                lpName					// The name of the file mapping object. If this parameter is NULL, the file mapping object is created without a name.
	); */
	printf("[*] Creating a RO file mapping for ntdll.dll on disk\n");

	HANDLE hNtdllFileMapping;
	try
	{
		hNtdllFileMapping = CreateFileMapping(hNtdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	}
	catch (const std::exception&)
	{
		printf("[!] Failed to create a RO file mapping for ntdll.dll\n");
		exit(1);
	}

	/* Maps a view of a file mapping into the address space of a calling process.
	LPVOID MapViewOfFile(
		HANDLE hFileMappingObject,		// A handle to a file mapping object.
		DWORD  dwDesiredAccess,			// The type of access to a file mapping object, which determines the page protection of the pages.
		DWORD  dwFileOffsetHigh,		// A high-order DWORD of the file offset where the view begins.
		DWORD  dwFileOffsetLow,			// A low-order DWORD of the file offset where the view is to begin.
		SIZE_T dwNumberOfBytesToMap		// The number of bytes of a file mapping to map to the view.
	); */
	printf("[*] Creating RO mapped file view of ntdll.dll on disk\n");

	LPVOID ntdllMappingAddress;
	try
	{
		ntdllMappingAddress = MapViewOfFile(hNtdllFileMapping, FILE_MAP_READ, 0, 0, 0);
	}
	catch (const std::exception&)
	{
		printf("[*] Failed creating RO mapped file view of ntdll.dll\n");
		exit(1);
	}

	// get a pointer to the beginning of the DOS header of the hooked ntdll.dll. This is at the beginning of the DLL
	printf("[*] Getting the DOS header from the loaded (hooked) ntdll.dll module.\n");

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)pHookedNtdllBaseAddress;

	/* Get the PE header based on the DLL base address plus the file address of new exe header (e_lfanew)
	typedef struct _IMAGE_NT_HEADERS {
		DWORD                   Signature;
		IMAGE_FILE_HEADER       FileHeader;
		IMAGE_OPTIONAL_HEADER32 OptionalHeader;
		} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32; */
	printf("[*] Getting the PE header: hooked ntdll.dll base address plus the file address of new exe header (e_lfanew).\n");

	PIMAGE_NT_HEADERS hookedNtHeader;
	try
	{
		hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pHookedNtdllBaseAddress + hookedDosHeader->e_lfanew);
	}
	catch (const std::exception&)
	{
		printf("[!] Failed getting the PE header");
		exit(1);
	}

	printf("[*] Iterating through each section of the IMAGE_FILE_HEADER->NumberOfSections field, looking for .text.\n");

	// NumberOfSections: The number of sections.This indicates the size of the section table, which immediately follows the headers. Max 96 sections.
	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++)
	{
		// The IMAGE_FIRST_SECTION macro returns a pointer to the first IMAGE_SECTION_HEADER. Incrementing the pointer goes to the next section header.
		// IMAGE_SIZEOF_SECTION_HEADER is a constant set to 40 (bytes)
		// hookedSectionHeader[n] = IMAGE_FIRST_SECTION(hookedNtHeader) + 40 bytes = next section offset
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		printf("\t[*] Section %i: %s\n", i, (char*)hookedSectionHeader->Name);

		// locate the .text section via string comapare against the section name field
		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text"))
		{
			printf("\t\t[*] Found the .text section, processing\n");

			// overwrite the loaded ntdll.text section with the clean one from disk
			/* Changes the protection on a region of committed pages in the virtual address space of the calling process.
			BOOL VirtualProtect(
				LPVOID lpAddress,		// A pointer an address that describes the starting page of the region of pages whose access protection attributes are to be changed.
				SIZE_T dwSize,			// The size of the region whose access protection attributes are to be changed, in bytes.
				DWORD  flNewProtect,	// The memory protection option. This parameter can be one of the memory protection constants.
				PDWORD lpflOldProtect	// A pointer to a variable that receives the previous access protection value of the first page in the specified region of pages.
			); */

			// start address of the current section header (.text) to overwrite
			LPVOID hookedVirtualAddressStart = (LPVOID)((DWORD_PTR)pHookedNtdllBaseAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress);

			// size of the .text section to overwrite
			SIZE_T hookedVirtualAddressSize = hookedSectionHeader->Misc.VirtualSize;
			printf("\t\t[*] The size of the .text section is %lld bytes\n", hookedVirtualAddressSize);

			// previous access protection value
			DWORD oldProtection = 0;

			printf("\t\t[*] Address of the hooked .text section: 0x%p\n", hookedVirtualAddressStart);

			printf("\t\t[*] Saving the hooked ntdll bytes to .\\hooked.txt\n");
			char* hookedBytes{ new char[hookedVirtualAddressSize] {} };
			memcpy_s(hookedBytes, hookedVirtualAddressSize, hookedVirtualAddressStart, hookedVirtualAddressSize);
			saveBytes(hookedBytes, "hooked.txt", hookedVirtualAddressSize);

			printf("\t\t[*] Changing memory protection status of the hooked .text section to RWX\n");

			bool isProtected;
			try
			{
				isProtected = VirtualProtect(hookedVirtualAddressStart, hookedVirtualAddressSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			}
			catch (const std::exception&)
			{
				printf("[!] Failed changing memory protection status of the hooked .text section\n");
				exit(1);
			}

			// copy the clean .text section of the on-disk ntdll.dll into the loaded ntdll.dll module's .text section
			/* Copies bytes between buffers, checking the size of the destination buffer against overflows.
			errno_t memcpy_s(
				void* dest,			// Destination buffer.
				size_t destSize,	// Size of the destination buffer, in bytes.
				const void* src,	// Source buffer.
				size_t count		// Number of characters to copy.
			); */

			LPVOID cleanVirtualAddressStart = (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress);

			printf("\t\t[*] Saving the clean ntdll bytes to .\\clean.txt\n");
			char* cleanBytes{ new char[hookedVirtualAddressSize] {} };
			memcpy_s(cleanBytes, hookedVirtualAddressSize, cleanVirtualAddressStart, hookedVirtualAddressSize);
			saveBytes(cleanBytes, "clean.txt", hookedVirtualAddressSize);

			delete[] hookedBytes;
			delete[] cleanBytes;

			printf("\t\t[*] Address of the clean .text section:  0x%p\n", cleanVirtualAddressStart);

			printf("\t\t[*] Copying the clean .text section into the hooked .text section\n");
			memcpy_s(hookedVirtualAddressStart, hookedVirtualAddressSize, cleanVirtualAddressStart, hookedVirtualAddressSize);

			printf("\t\t[*] Changing memory protection status of the hooked .text section back\n");
			try
			{
				isProtected = VirtualProtect(hookedVirtualAddressStart, hookedVirtualAddressSize, oldProtection, &oldProtection);
			}
			catch (const std::exception&)
			{
				printf("[!] Failed changing memory protection status of the hooked .text section back");
				exit(1);
			}
		}
	}

	CloseHandle(hCurrentProcess);
	CloseHandle(hNtdllFile);
	CloseHandle(hNtdllFileMapping);
	FreeLibrary(hNtdllModule);

	printf("[!] Unhooking complete!");

	return 0;
}