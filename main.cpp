#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <functional>

#include <Windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>

#pragma comment(lib, "dbghelp.lib")

class hookchecker {
public:
	enum : uint8_t {
		hk_all,
		hk_inline,
		hk_bp,
		hk_hwbp,
		hk_iat,
	};

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

	bool check(uint8_t& type) {

		if (type == hk_all || type > hk_iat) {
			std::cout << "unknown type\n";
			return false;
		}

		if (type == hk_all || type == hk_inline) {
			if (check_inline()) {
				type = hk_inline;
				return true;
			}
		}

		if (type == hk_all || type == hk_bp) {
			if (check_bp()) {
				type = hk_bp;
				return true;
			}
		}

		if (type == hk_all || type == hk_hwbp) {
			if (check_hwbp()) {
				type = hk_hwbp;
				return true;
			}
		}

		if (type == hk_all || type == hk_iat) {
			if (check_iat()) {
				type = hk_iat;
				return true;
			}
		}

		return false;
	}

	bool unhook(uint8_t& type) {

		if (type == hk_all || type > hk_iat) {
			std::cout << "unknown type\n";
			return false;
		}

		switch (type) {
		case hk_inline:	return unhook_inline();
		case hk_bp:		return unhook_bp();
		case hk_hwbp:	return unhook_hwbp();
		case hk_iat:	return unhook_iat();
		default:		return false;
		}
	}

private:
	bool check_inline() {
		std::cout << "checking inline hook\n";
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

	bool check_bp() {
		std::cout << "checking breakpoint(int3) hook\n";

		if (*(uint8_t*)_active_function == 0xCC) {
			std::cout << "INT3 instruction found!\n";
			return true;
		}

		std::cout << "no INT3 instruction found\n";
		return false;
	}

	bool check_hwbp() {
		std::cout << "checking hardware breakpoint hook\n";

		bool is_hooked = false;

		auto func = [this](HANDLE thread, DWORD pid, DWORD tid) {
			CONTEXT ctx = { 0 };
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if (!GetThreadContext(thread, &ctx)) {
				std::cout << "could not get thread context for thread " << tid << "\n";
				return false;
			}

			for (int i = 0; i < 4; i++) {
				uintptr_t addr = ((uintptr_t*)&ctx.Dr0)[i];
				if (addr == (uintptr_t)_active_function) {
					std::cout << "function found in thread " << tid << " in debug register Dr" << i << "\n";
					return true;
				}
			}

			return false;
		};

		if (!for_each_thread(func, is_hooked))
			std::cout << "could not run check for each thread\n";

		return is_hooked;
	}

	bool check_iat() {
		std::cout << "checking IAT hook\n";

		uint8_t* base = get_process_base();
		PIMAGE_DOS_HEADER dos;
		PIMAGE_NT_HEADERS nt;
		PIMAGE_IMPORT_DESCRIPTOR imports, target;
		PIMAGE_THUNK_DATA othunk, fthunk;

		if (!load_headers(base, &dos, &nt, nullptr)) {
			std::cout << "could not load process headers\n";
			return false;
		}

		if (!get_iat_thunks(base, &othunk, &fthunk)) {
			std::cout << "could not get thunks\n";
			return false;
		}

		uintptr_t min_addr = (uintptr_t)_active_dos;
		uintptr_t max_addr = (uintptr_t)_active_dos + _active_nt->OptionalHeader.SizeOfImage;

		while (!(othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && othunk->u1.AddressOfData) {

			PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(base + othunk->u1.AddressOfData);
			if (!strcmp(_function, ibn->Name)) {

				if (min_addr <fthunk->u1.Function && max_addr > fthunk->u1.Function)
					return false;
				else
					return true;
			}

			othunk++;
			fthunk++;
		}

		return false;
	}

	bool unhook_inline() {
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

	bool unhook_bp() {
		std::cout << "unhooking breakpoint (INT3) hook\n";

		DWORD old = 0;
		if (!VirtualProtect(_active_function, 1, PAGE_EXECUTE_READWRITE, &old)) {
			std::cout << "could not change page protection to PAGE_EXECUTE_READWRITE\n";
			return false;
		}

		*(uint8_t*)_active_function = *(uint8_t*)_loaded_function;

		if (!VirtualProtect(_active_function, 1, old, &old)) {
			std::cout << "could not revert page protection changes but unhooked anyways. page is now RWX protected\n";
			return true;
		}

		return true;
	}

	bool unhook_hwbp() {

		bool success = false;

		auto func = [this](HANDLE thread, DWORD pid, DWORD tid) {

			CONTEXT ctx = { 0 };
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if (!GetThreadContext(thread, &ctx)) {
				std::cout << "could not get thread context for thread " << tid << "\n";
				return false;
			}

			for (int i = 0; i < 4; i++) {
				uintptr_t& addr = ((uintptr_t*)&ctx.Dr0)[i];
				if (addr == (uintptr_t)_active_function) {
					std::cout << "function found in thread " << tid << " in debug register Dr" << i << "\n";
					std::cout << "erasing register\n";

					addr = 0;

					if (!SetThreadContext(thread, &ctx)) {
						std::cout << "could not erase register\n";
						return false;
					}

					return true;
				}
			}
		};

		if (!for_each_thread(func, success)) {
			std::cout << "could not run procedure for each thread\n";
			return success;
		}

		return success;
	}

	bool unhook_iat() {

		uint8_t* base = get_process_base();
		PIMAGE_DOS_HEADER dos;
		PIMAGE_NT_HEADERS nt;
		PIMAGE_IMPORT_DESCRIPTOR imports, target;
		PIMAGE_THUNK_DATA othunk, fthunk;

		if (!load_headers(base, &dos, &nt, nullptr)) {
			std::cout << "could not load process headers\n";
			return false;
		}

		if (!get_iat_thunks(base, &othunk, &fthunk)) {
			std::cout << "could not get thunks\n";
			return false;
		}
		
		uintptr_t min_addr = (uintptr_t)_active_dos;
		uintptr_t max_addr = (uintptr_t)_active_dos + _active_nt->OptionalHeader.SizeOfImage;

		while (!(othunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && othunk->u1.AddressOfData) {

			PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(base + othunk->u1.AddressOfData);
			if (!strcmp(_function, ibn->Name)) {

				std::cout << "function " << std::quoted(_function) << " is pointing at " << fthunk->u1.Function << "\n";
				std::cout << "scanning for original function address using 20 byte match...\n"; // change this to length disassembled value

				for (uint8_t* addr = (uint8_t*)min_addr; (uintptr_t)addr < max_addr; addr++) {
					if (!memcmp(addr, _loaded_function, min(max_addr - (uintptr_t)addr, 20))) {
						std::cout << "original function located at 0x" << (void*)addr << "\n";
						std::cout << "overwriting iat entry\n";

						DWORD old = 0;
						if (!VirtualProtect(&fthunk->u1.Function, sizeof(uintptr_t), PAGE_READWRITE, &old)) {
							std::cout << "could not change page protection to PAGE_READWRITE\n";
							return false;
						}

						fthunk->u1.Function = (uintptr_t)addr;

						if (!VirtualProtect(&fthunk->u1.Function, sizeof(uintptr_t), old, &old)) {
							std::cout << "could not revert page protection changes but unhooked anyways. page is now RW protected\n";
							return true;
						}

						return true;
					}
				}
			}

			othunk++;
			fthunk++;
		}

		return false;
	}

private:
	bool for_each_thread(std::function<bool(HANDLE, DWORD, DWORD)> func, bool& out) {

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			std::cout << "could not get snapshot handle\n";
			return false;
		}

		THREADENTRY32 te;
		te.dwSize = sizeof(te);

		DWORD pid = GetCurrentProcessId();
		DWORD tid = GetCurrentThreadId();

		if (!Thread32First(snapshot, &te)) {
			std::cout << "could not get first thread\n";
			CloseHandle(snapshot);
			return false;
		}

		do {

			if (te.th32OwnerProcessID != pid)
				continue;

			HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, te.th32ThreadID);
			if (thread == INVALID_HANDLE_VALUE)
				continue;

			out = func(thread, pid, tid);

			CloseHandle(thread);

		} while (Thread32Next(snapshot, &te));

		CloseHandle(snapshot);

		return true;
	}

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

	void* resolve_function(PIMAGE_DOS_HEADER dos, PIMAGE_NT_HEADERS nt, const char* func) {
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

	bool load_headers(uint8_t* data, PIMAGE_DOS_HEADER* dos, PIMAGE_NT_HEADERS* nt, PIMAGE_SECTION_HEADER* sec) {

		PIMAGE_DOS_HEADER _dos;
		PIMAGE_NT_HEADERS _nt;
		PIMAGE_SECTION_HEADER _sec;

		_dos = (PIMAGE_DOS_HEADER)data;
		if (_dos->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		_nt = (PIMAGE_NT_HEADERS)(data + _dos->e_lfanew);
		if (_nt->Signature != IMAGE_NT_SIGNATURE)
			return false;

		_sec = IMAGE_FIRST_SECTION(_nt);

		if (dos) *dos = _dos;
		if (nt)  *nt = _nt;
		if (sec) *sec = _sec;

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

	uint8_t* get_process_base() {
#if 0
		PPEB						peb;
#ifdef _WIN64
		peb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock;
#else
		peb = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock;
#endif

		PLDR_DATA_TABLE_ENTRY data = (PLDR_DATA_TABLE_ENTRY)peb->Ldr->InMemoryOrderModuleList.Flink;
		if (!data || !data->FullDllName.Buffer) {
			std::cout << "could not get name of current process\n";
		}

		uint8_t* base = (uint8_t*)GetModuleHandleW(data->FullDllName.Buffer);
#else

		char procname[MAX_PATH] = { 0 };
		DWORD size = MAX_PATH;
		QueryFullProcessImageNameA(GetCurrentProcess(), 0, procname, &size);

		uint8_t* base = (uint8_t*)GetModuleHandleA(procname);
#endif

		return base;
	}

	bool get_iat_thunks(uint8_t* base, PIMAGE_THUNK_DATA* othunk, PIMAGE_THUNK_DATA* fthunk) {

		DWORD size;
		PIMAGE_IMPORT_DESCRIPTOR imports, target;
		
		imports = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(base, true, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, nullptr);
		if (!imports) {
			std::cout << "could not get the import descriptor from the file headers\n";
			return false;
		}

		target = nullptr;
		while (imports->Name) {
			char* name = (char*)(base + imports->Name);

			if (!_strcmpi(_module, name) || !(_strcmpi((std::string(_module) + ".dll").c_str(), name))) {
				target = imports;
				break;
			}

			imports++;
	}

		if (!target) {
			std::cout << "could not find module in import table\n";
			return false;
		}

		if (othunk) *othunk = PIMAGE_THUNK_DATA(base + target->OriginalFirstThunk);
		if (fthunk) *fthunk = PIMAGE_THUNK_DATA(base + target->FirstThunk);

		return true;
	}

private:
	const char* _module = nullptr;
	const char* _function = nullptr;

	HMODULE					_active_hmod = nullptr;
	PIMAGE_DOS_HEADER		_active_dos = nullptr, _disk_dos = nullptr;
	PIMAGE_NT_HEADERS		_active_nt = nullptr, _disk_nt = nullptr;
	PIMAGE_SECTION_HEADER	_active_sec = nullptr, _disk_sec = nullptr;

	std::vector<uint8_t>	_buffer;
	std::string				_full_filename;

	void* _active_function = nullptr;
	void* _loaded_function = nullptr;

	size_t _size = sizeof(void*) == 4 ? 5 : 14;	// from my expecience minimum inline hook length (bytes) on x86 is 5 and x64 is 14
};

int main() {


	// testing on GetUserNameA
	void* func = GetUserNameA;

	// make page writable
	//DWORD old;
	//VirtualProtect(func, 10, PAGE_EXECUTE_READWRITE, &old);

	//// nop first 10 bytes to simulate hook
	//memset(func, 0x90, 10);

	//// recover page protection
	//VirtualProtect(func, 10, old, &old);

	// check if function is edited
	hookchecker checker("Advapi32", "GetUserNameA");
	uint8_t type = hookchecker::hk_iat;

	if (checker.check(type)) {
		std::cout << "function entry is changed\n";
	
		// recover original function
		checker.unhook(type);

		// test function
		char buf[MAX_PATH] = { 0 };
		DWORD size = MAX_PATH;
		GetUserNameA(buf, &size);
		std::cout << buf << "\n";
	}
	
	return 0;
}
