#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <Windows.h>
#include <filesystem>
#include <fstream>

class hookchecker {
public:

	hookchecker(const char* module, const char* function, const std::string& path = "") :
		_module(module), _function(function), _full_filename(path) {

		_active_hmod = GetModuleHandleA(_module);
		if (!_active_hmod) {
			std::cout << "could not get module handle\n";
			return;
		}

		if (!resolve_filename())
			return;

		if (!load_file())
			return;

		if (!load_headers((uint8_t*)_active_hmod, &_active_dos, &_active_nt, &_active_sec)) {
			std::cout << "could not get valid headers\n";
			return;
		}

		if (!load_headers(_buffer.data(), &_disk_dos, &_disk_nt, &_disk_sec)) {
			std::cout << "could not get valid headers\n";
			return;
		}

		if (!resolve_functions()) {
			std::cout << "could not resolve required functions\n";
			return;
		}
	}

	bool check() {
		std::cout << "checking " << _size << " bytes\n";

		if (!_active_function || !_loaded_function) {
			std::cout << "required functions not loaded\n";
			return false;
		}

		if (!memcmp(_active_function, _loaded_function, _size)) {
			return false;
		}

		return true;
	}

	bool unhook() {
		std::cout << "recovering " << _size << " bytes\n";

		if (!_active_function || !_loaded_function) {
			std::cout << "required functions not loaded\n";
			return false;
		}

		DWORD old;
		if (!VirtualProtect(_active_function, _size, PAGE_EXECUTE_READWRITE, &old)) {
			std::cout << "could not change page protection\n";
			return false;
		}

		memcpy(_active_function, _loaded_function, _size);

		if (!VirtualProtect(_active_function, _size, old, &old)) {
			std::cout << "could not change page protection\n";
			return false;
		}

		std::cout << "recovered bytes\n";

		return true;
	}

private:

	bool resolve_functions() {

		void* active_func = GetProcAddress(_active_hmod, _function);
		if (!active_func) {
			std::cout << "could not resolve specified function: " << std::quoted(_function) << "\n";
			return false;
		}

		void* loaded_func = resolve_function(_disk_dos, _disk_nt, _function);
		if (!loaded_func) {
			std::cout << "could not resolve function address in file\n";
			return false;
		}

		std::cout << "active function: 0x" << active_func << "\n";
		std::cout << "disk function:   0x" << loaded_func << "\n";

		_active_function = active_func;
		_loaded_function = loaded_func;

		return true;
	}

	static void* resolve_function(PIMAGE_DOS_HEADER dos, PIMAGE_NT_HEADERS nt, const char* func) {
		uintptr_t base = (uintptr_t)dos;

		auto exports = rva2real<PIMAGE_EXPORT_DIRECTORY>(dos, nt, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		auto functions = rva2real<DWORD*>(dos, nt, exports->AddressOfFunctions);
		auto ordinals = rva2real<WORD*>(dos, nt, exports->AddressOfNameOrdinals);
		auto names = rva2real<DWORD*>(dos, nt, exports->AddressOfNames);

		for (int i = 0; i < exports->NumberOfNames; i++) {
			char* fname = rva2real<char*>(dos, nt, names[i]);
			if (!strcmp(fname, func)) {
				return rva2real<void*>(dos, nt, functions[ordinals[i]]);
			}
		}

		return nullptr;
	}

	bool resolve_filename() {
		using namespace std::filesystem;

		if (_full_filename.length() && !exists(_full_filename)) {
			std::cout << "invalid file specified\n";
			return false;
		}

		if (!exists(_module)) {
			std::cout << "module is no direct path. resolving...\n";
			
			char modulename[MAX_PATH] = { 0 };
			if (!GetModuleFileNameA(_active_hmod, modulename, MAX_PATH))
				return "";

			std::string resolved_mod = modulename;

			if (!resolved_mod.length()) {
				std::cout << "could not resolve path\n";
				return false;
			}
			else if (!exists(resolved_mod)) {
				std::cout << "resolved to " << std::quoted(resolved_mod) << " but could not find on disk\n";
				return false;
			}
			else {
				std::cout << "resolved to " << std::quoted(resolved_mod) << "\n";
				_full_filename = resolved_mod;
			}
		}		
	}

	bool load_file() {
		using namespace std::filesystem;

		size_t filesize = 0;
		std::ifstream f(_full_filename, std::ios::binary);
		f.unsetf(std::ios::skipws);

		f.seekg(0, std::ios::end);
		filesize = f.tellg();
		f.seekg(0, std::ios::beg);

		_buffer.resize(filesize);
		_buffer.insert(_buffer.begin(), std::istream_iterator<uint8_t>(f), std::istream_iterator<uint8_t>());

		f.close();

		return true;
	}

	static bool load_headers(uint8_t* data, PIMAGE_DOS_HEADER* dos, PIMAGE_NT_HEADERS* nt, PIMAGE_SECTION_HEADER* sec) {
		auto& _dos = *dos;
		auto& _nt = *nt;
		auto& _sec = *sec;

		_dos = (PIMAGE_DOS_HEADER)data;
		if (_dos->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		_nt = (PIMAGE_NT_HEADERS)(data + _dos->e_lfanew);
		if (_nt->Signature != IMAGE_NT_SIGNATURE)
			return false;

		_sec = IMAGE_FIRST_SECTION(_nt);

		return true;
	}

	template <typename T>
	static T rva2real(PIMAGE_DOS_HEADER dos, PIMAGE_NT_HEADERS nt, uint32_t rva) {
		if (!rva) return nullptr;

		PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
		uintptr_t _real = (uintptr_t)rva;
		uintptr_t _dos = (uintptr_t)dos;

		for (size_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
			if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize)
				return T(_dos + (rva - sec->VirtualAddress + sec->PointerToRawData));

			sec++;
		}

		return T(nullptr);
	}

private:
	const char* _module = nullptr;
	const char* _function = nullptr;

	HMODULE					_active_hmod = nullptr;
	PIMAGE_DOS_HEADER		_active_dos = nullptr, _disk_dos = nullptr;
	PIMAGE_NT_HEADERS		_active_nt = nullptr,  _disk_nt = nullptr;
	PIMAGE_SECTION_HEADER	_active_sec = nullptr, _disk_sec = nullptr;

	std::vector<uint8_t>	_buffer;
	std::string				_full_filename;

	void* _active_function = nullptr;
	void* _loaded_function = nullptr;

	size_t _size = sizeof(void*) == 4 ? 5 : 14;
};


int main() {

	// testing on GetUserNameA
	void* func = GetUserNameA;
	
	// make page writable
	DWORD old;
	VirtualProtect(func, 10, PAGE_EXECUTE_READWRITE, &old);
	
	// nop first 10 bytes to simulate hook
	memset(func, 0x90, 10);

	// recover page protection
	VirtualProtect(func, 10, old, &old);

	// check if function is edited
	hookchecker checker("Advapi32", "GetUserNameA");

	if (checker.check()) {
		std::cout << "function entry is changed\n";

		// recover original function
		checker.unhook();
	
		// test function
		char buf[MAX_PATH] = { 0 };
		DWORD size = MAX_PATH;
		GetUserNameA(buf, &size);
		std::cout << buf << "\n";
	}

	return 0;
}
