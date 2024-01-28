#include <windows.h>
#include <Psapi.h>
#include <locale.h>
#include <stdio.h>

//IATHook的原理，就是修改IAT表中的地址，替换成我们自已函数的地址

/**
 * 安装IATHook
 */
VOID installIATHook(LPVOID imageBase, DWORD oldFunc, DWORD newFunc)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;

	dos = (PIMAGE_DOS_HEADER)imageBase;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY* dir = opt->DataDirectory;

	DWORD importRva = dir[1].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)imageBase + importRva);

	while (importDir->Name)
	{
		//遍历FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)imageBase + FirstThunkRva);

		while (FirstThunk->u1.Function)
		{
			if (FirstThunk->u1.Function == oldFunc)
			{
				printf("替换成功\n");

				// 开启写权限
				DWORD oldProtected;
				VirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &oldProtected);

				FirstThunk->u1.Function = newFunc;

				// 关闭写保护
				VirtualProtect(FirstThunk, 4, oldProtected, &oldProtected);

				break;
			}

			FirstThunk++;
		}
		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * 卸载IATHook
 */
VOID unInstallIATHook(LPVOID imageBase, DWORD oldFunc, DWORD newFunc)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;

	dos = (PIMAGE_DOS_HEADER)imageBase;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	IMAGE_DATA_DIRECTORY* dir = opt->DataDirectory;

	DWORD importRva = dir[1].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)imageBase + importRva);

	while (importDir->Name)
	{
		//遍历FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)imageBase + FirstThunkRva);

		while (FirstThunk->u1.Function)
		{
			if (FirstThunk->u1.Function == newFunc)
			{
				printf("恢复成功\n");

				// 开启写权限
				DWORD oldProtected;
				VirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &oldProtected);

				FirstThunk->u1.Function = oldFunc;

				// 关闭写保护
				VirtualProtect(FirstThunk, 4, oldProtected, &oldProtected);

				break;
			}

			FirstThunk++;
		}
		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * 注意，你要替换的函数，应该与你写的函数参数保持一致
 */
int WINAPI MyMsgBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	printf("获取到的参数 %d %s %s %d\n", hWnd, lpText, lpCaption, uType);

	typedef int (WINAPI* MsgBox)(HWND, LPCSTR, LPCSTR, UINT);

	//注意这里不能直接调用MessageBoxW，因为已经被我们替换了，直接调会死循环
	MsgBox mbw = (MsgBox)GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

	int ret = mbw(hWnd, lpText, lpCaption, uType);

	printf("获取到的返回值 %d\n", ret);

	return ret;
}

int main()
{
	setlocale(LC_ALL, "CHS");
	HANDLE hProcess = GetCurrentProcess();
	HMODULE hModule = GetModuleHandle(NULL);

	MODULEINFO mi{ 0 };
	GetModuleInformation(hProcess, hModule, &mi, sizeof(mi));

	//获取当前进程的ImageBase
	LPVOID imageBase = mi.lpBaseOfDll;

	//获取原函数地址
	FARPROC msgBoxA = GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

	//安装IATHook
	installIATHook(imageBase, (DWORD)msgBoxA, (DWORD)MyMsgBoxA);

	//测试
	MessageBoxA(NULL, "你好", "你好", MB_OK);

	//卸载IATHook
	unInstallIATHook(imageBase, (DWORD)msgBoxA, (DWORD)MyMsgBoxA);

	//测试
	MessageBoxA(NULL, "你好！", "你好！", MB_OK);

	return 0;
}