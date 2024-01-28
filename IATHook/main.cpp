#include <windows.h>
#include <Psapi.h>
#include <locale.h>
#include <stdio.h>

//IATHook��ԭ�������޸�IAT���еĵ�ַ���滻���������Ѻ����ĵ�ַ

/**
 * ��װIATHook
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
		//����FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)imageBase + FirstThunkRva);

		while (FirstThunk->u1.Function)
		{
			if (FirstThunk->u1.Function == oldFunc)
			{
				printf("�滻�ɹ�\n");

				// ����дȨ��
				DWORD oldProtected;
				VirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &oldProtected);

				FirstThunk->u1.Function = newFunc;

				// �ر�д����
				VirtualProtect(FirstThunk, 4, oldProtected, &oldProtected);

				break;
			}

			FirstThunk++;
		}
		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * ж��IATHook
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
		//����FirstThunk
		DWORD FirstThunkRva = importDir->FirstThunk;

		PIMAGE_THUNK_DATA32 FirstThunk = PIMAGE_THUNK_DATA32((LPBYTE)imageBase + FirstThunkRva);

		while (FirstThunk->u1.Function)
		{
			if (FirstThunk->u1.Function == newFunc)
			{
				printf("�ָ��ɹ�\n");

				// ����дȨ��
				DWORD oldProtected;
				VirtualProtect(FirstThunk, 4, PAGE_EXECUTE_READWRITE, &oldProtected);

				FirstThunk->u1.Function = oldFunc;

				// �ر�д����
				VirtualProtect(FirstThunk, 4, oldProtected, &oldProtected);

				break;
			}

			FirstThunk++;
		}
		importDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)importDir + 20);
	}
}

/**
 * ע�⣬��Ҫ�滻�ĺ�����Ӧ������д�ĺ�����������һ��
 */
int WINAPI MyMsgBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	printf("��ȡ���Ĳ��� %d %s %s %d\n", hWnd, lpText, lpCaption, uType);

	typedef int (WINAPI* MsgBox)(HWND, LPCSTR, LPCSTR, UINT);

	//ע�����ﲻ��ֱ�ӵ���MessageBoxW����Ϊ�Ѿ��������滻�ˣ�ֱ�ӵ�����ѭ��
	MsgBox mbw = (MsgBox)GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

	int ret = mbw(hWnd, lpText, lpCaption, uType);

	printf("��ȡ���ķ���ֵ %d\n", ret);

	return ret;
}

int main()
{
	setlocale(LC_ALL, "CHS");
	HANDLE hProcess = GetCurrentProcess();
	HMODULE hModule = GetModuleHandle(NULL);

	MODULEINFO mi{ 0 };
	GetModuleInformation(hProcess, hModule, &mi, sizeof(mi));

	//��ȡ��ǰ���̵�ImageBase
	LPVOID imageBase = mi.lpBaseOfDll;

	//��ȡԭ������ַ
	FARPROC msgBoxA = GetProcAddress(LoadLibrary(TEXT("user32.dll")), "MessageBoxA");

	//��װIATHook
	installIATHook(imageBase, (DWORD)msgBoxA, (DWORD)MyMsgBoxA);

	//����
	MessageBoxA(NULL, "���", "���", MB_OK);

	//ж��IATHook
	unInstallIATHook(imageBase, (DWORD)msgBoxA, (DWORD)MyMsgBoxA);

	//����
	MessageBoxA(NULL, "��ã�", "��ã�", MB_OK);

	return 0;
}