#pragma once
#include <Windows.h>

#define IN 
#define OUT

#define OBF(s) ([]() { \
    static lazy_importer::utility::obfuscate<sizeof(s)> out{ s }; \
    static char buffer[sizeof(s)]; \
    out.decode(buffer); \
    return buffer; \
}())

#define IMPORT(x) reinterpret_cast<decltype(&x)>(lazy_importer::find_export(lazy_importer::hash::ct_hash(#x)))
#define IMPORT_MODULE(dll) reinterpret_cast<HMODULE>(IMPORT(LoadLibraryA)(OBF(dll)))

namespace lazy_importer 
{
	namespace windows 
	{
		typedef struct _LIST_ENTRY {
			struct _LIST_ENTRY* Flink;
			struct _LIST_ENTRY* Blink;
		} LIST_ENTRY, * PLIST_ENTRY, PRLIST_ENTRY;

		typedef struct _STRING32
		{
			USHORT Length;
			USHORT MaximumLength;
			ULONG Buffer;
		} STRING32, * PSTRING32, UNICODE_STRING32, *PUNICODE_STRING32;

		typedef struct _PEB_LDR_DATA
		{
			ULONG Length;
			BOOLEAN Initialized;
			HANDLE SsHandle;
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
			PVOID EntryInProgress;
			BOOLEAN ShutdownInProgress;
			HANDLE ShutdownThreadId;
		} PEB_LDR_DATA, * PPEB_LDR_DATA;
		
		typedef struct _PEB {
			BOOLEAN InheritedAddressSpace;
			BOOLEAN ReadImageFileExecOptions;
			BOOLEAN BeingDebugged;
			BYTE Padding[1];
			HANDLE Mutant;
			PVOID ImageBaseAddress;
			PPEB_LDR_DATA Ldr;
		} PEB, * PPEB;

		typedef struct _UNICODE_STRING
		{
			USHORT Length;
			USHORT MaximumLength;
			_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
		} UNICODE_STRING, * PUNICODE_STRING;

		typedef struct _LDR_DATA_TABLE_ENTRY64
		{
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY InMemoryOrderLinks;
			LIST_ENTRY InInitializationOrderLinks;
			PVOID DllBase;
			PVOID EntryPoint; // PDLL_INIT_ROUTINE
			ULONG SzeOfImage;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
		} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

		typedef struct _LDR_DATA_TABLE_ENTRY32
		{
			LIST_ENTRY32 InLoadOrderLinks;
			LIST_ENTRY32 InMemoryOrderLinks;
			union
			{
				LIST_ENTRY32 InInitializationOrderLinks;
				LIST_ENTRY32 InProgressLinks;
			};
			PVOID DllBase;
			PVOID EntryPoint;
			ULONG SizeOfImage;
			UNICODE_STRING32 FullDllName;
			UNICODE_STRING32 BaseDllName;
		} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
	}
	namespace utility
	{
		constexpr uint64_t key = 0xC0FFEE;

		template <size_t N>
		struct obfuscate {
			volatile uint8_t c[N]{};

			constexpr obfuscate(const char(&s)[N]) {
				for (size_t i = 0; i < N; ++i) {
					const uint8_t kb = static_cast<uint8_t>((key + i));
					c[i] = static_cast<uint8_t>(static_cast<uint8_t>(s[i]) ^ kb);
				}
			}

			// must be const (you call it on a const object)
			__forceinline void decode(char* out) const noexcept {
				for (size_t i = 0; i < N; ++i) {
					const uint8_t kb = static_cast<uint8_t>((key + i));
					out[i] = static_cast<char>(c[i] ^ kb);
				}
			}
		};
	};
	namespace hash 
	{
		// FNV-1a hashing algorithm
		constexpr uint64_t prime = 1099511628211ULL;

		// regular C strings
		constexpr uint64_t hash_string(IN const char* string)
		{
			uint64_t hash = 1469598103934665603ULL;

			while (*string) {
				hash ^= (uint8_t)(*string++);
				hash *= prime;
			}

			return hash;
		}

		// for hashing wide strings
		constexpr uint64_t hash_string(IN wchar_t* string)
		{
			uint64_t hash = 1469598103934665603ULL;

			while (*string) 
			{
				hash ^= (uint8_t)(*string++);
				hash *= prime;
			}

			return hash;
		}

		constexpr uint64_t hash_string(IN const ULONG addr) 
		{
			return hash_string(reinterpret_cast<wchar_t*>(addr));
		}

		// compile time string hashing
		template <size_t N>
		constexpr uint64_t ct_hash(const char(&str)[N]) 
		{
			uint64_t hash = 1469598103934665603ull;
			for (size_t i = 0; i < N - 1; ++i)
			{  // N-1 to skip null terminator
				hash ^= static_cast<uint64_t>(str[i]);
				hash *= prime;
			}
			return hash;
		}
	}

	using namespace windows;

#ifdef _M_X64
	using PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS64;
	using PLDR_DATA_TABLE_ENTRY = LDR_DATA_TABLE_ENTRY64*;
#else
	using PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS32;
	using PLDR_DATA_TABLE_ENTRY = LDR_DATA_TABLE_ENTRY32*;
#endif

	__forceinline PEB* get_peb() 
	{
#ifdef _M_X64
		return (PEB*)__readgsqword(0x60);
#else
		return (PEB*)__readfsdword(0x30);
#endif
	}

	__forceinline PBYTE get_module_base(IN uint64_t dll_hash) {
		const auto ldr = (PPEB_LDR_DATA)get_peb()->Ldr;

		const auto* head = &ldr->InLoadOrderModuleList;
		const auto* current = ldr->InLoadOrderModuleList.Flink;

		while (current != head) {
			const auto* ldr_data = (PLDR_DATA_TABLE_ENTRY)current;

			const auto wide_module_name = ldr_data->BaseDllName.Buffer;

			if (dll_hash == hash::hash_string(wide_module_name))
			{
				return (BYTE*)ldr_data->DllBase;
			}

			current = current->Flink;
		}

		return nullptr;
	}
	__forceinline uint64_t get_export(IN uint64_t dll_hash, IN uint64_t function_hash) {

		const auto module_base = get_module_base(dll_hash);

		const auto dos = (PIMAGE_DOS_HEADER)module_base;
		const auto nt = (PIMAGE_NT_HEADERS)(module_base + dos->e_lfanew);

		const auto export_directory = (PIMAGE_EXPORT_DIRECTORY)(module_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		const auto functions = (DWORD*)(module_base + export_directory->AddressOfFunctions);
		const auto names = (uint32_t*)(module_base + export_directory->AddressOfNames);
		const auto ordinals = (uint16_t*)(module_base + export_directory->AddressOfNameOrdinals);

		for (int i = 0; i < export_directory->NumberOfFunctions; i++) 
		{
			const auto offset = (void*)(module_base + functions[ordinals[i]]);
			const auto name = (const char*)(module_base + names[i]);
			if (function_hash == hash::hash_string(name))
			{
				return (uint64_t)(offset);
			}
		}

		return -1;
	}

	__forceinline uint64_t find_export(IN uint64_t function_hash) {
		const auto ldr = (PPEB_LDR_DATA)get_peb()->Ldr;

		const auto* head = &ldr->InLoadOrderModuleList;
		const auto* current = ldr->InLoadOrderModuleList.Flink;

		while (current != head) 
		{
			const auto* ldr_data = (PLDR_DATA_TABLE_ENTRY)current;
			
			uint64_t hashed_module_name = hash::hash_string(ldr_data->BaseDllName.Buffer);
	
			if (get_export(hashed_module_name, function_hash) != -1)
			{
				return get_export(hashed_module_name, function_hash);
			}

			current = current->Flink;
		}

		return -1;
	}
}
