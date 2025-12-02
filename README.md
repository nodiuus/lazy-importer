# lazy-importer
Single header Windows-based lazy-importer that dynamically generates function stubs to call functions in an obfuscated manner.

Usage:

```cpp
#include "importer.hpp"

std::uint32_t get_pid(const std::wstring& str)
{
	auto snapshot = IMPORT(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W pe{};
	pe.dwSize = sizeof(PROCESSENTRY32W);

	if (!IMPORT(Process32FirstW)(snapshot, &pe))
		return IMPORT(CloseHandle)(snapshot), 0;

	do
	{
		if (std::wstring(pe.szExeFile).find(str) != std::wstring::npos)
			return IMPORT(CloseHandle)(snapshot), pe.th32ProcessID;
	} while (IMPORT(Process32NextW)(snapshot, &pe));

	IMPORT(CloseHandle)(snapshot);
	return 0;
}

int main() {
	HMODULE user32 = IMPORT_MODULE("user32.dll");
	if (!user32) {
		return -1;
	}
  IMPORT(OutputDebugStringA)("hello hello hello\n");
	DWORD pid = get_pid(L"Notepad.exe");
	std::printf("pid: %d\n", pid);
  IMPORT(MessageBoxA)(NULL, "WHOS THERE", "RAHHHHHHHHHHH", MB_OK); // from user32.dll
}
```
