#include <windows.h>
#include <stdio.h>
#include <tchar.h>

//����ʱ����������ַ���ˣ������̶���ַ

//�������Ҳ���ʱadd�����ĵ�ַ����Ҫ�ĳ��������ѵ�
//ֱ���ú�����������ַ����Ϊ��VS�У�������תһ��������JMPһ�²Ż��������ĺ�����ַ��ֱ���ú���������ַ��������
DWORD addAddress = 0x00412A70;
DWORD oldJmp = addAddress + 16 + 5;
DWORD x = 0;
DWORD y = 0;
TCHAR szBuffer[MAX_PATH]{ 0 };

int installInlineHook(HANDLE hProcess, DWORD oldFunc, DWORD newFunc, DWORD offset, DWORD size, LPVOID* oldData)
{
	if (size < 5)
	{
		printf("��ת����ռ��5���ֽڣ�����С��5���ֽ�\n");
		return -1;
	}

	//���㿪ʼ��ַ
	DWORD start = oldFunc + offset;

	//�����ڴ棬���ڱ����滻������
	LPBYTE oldBuf = (LPBYTE)malloc(size);
	memset(oldBuf, 0, size);
	ReadProcessMemory(hProcess, (LPCVOID)(start), oldBuf, size, NULL);

	//����������Ҫ���E9 �����Ӳ����ΪX
	//X = ����Ҫ��ת�ĵ�ַ - E9����ָ�����һ�е�ַ
	//E9����ָ�����һ�е�ַ = ��ǰ��ַ + 5
	//X = ����Ҫ��ת�ĵ�ַ - ��ǰ��ַ - 5
	DWORD address = newFunc - start - 5;

	// ����дȨ��
	DWORD oldProtected;
	VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtected);

	//�滻ԭ�ȵ�Ӳ����
	*(LPBYTE)start = 0xE9;
	*(LPDWORD)((LPBYTE)start + 1) = address;

	// �ر�д����
	VirtualProtect((LPVOID)start, size, oldProtected, &oldProtected);

	*oldData = oldBuf;

	return 0;
}

VOID unInstallInlineHook(HANDLE hProcess, DWORD oldFunc, DWORD offset, DWORD size, LPVOID oldData)
{
	//���㿪ʼ��ַ
	DWORD start = oldFunc + offset;

	// ����дȨ��
	DWORD oldProtected;
	VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtected);

	//�滻ԭ�ȵ�Ӳ����
	WriteProcessMemory(hProcess, (LPVOID)start, oldData, size, NULL);

	// �ر�д����
	VirtualProtect((LPVOID)start, size, oldProtected, &oldProtected);
}

extern "C" __declspec(naked) void myAdd()
{
	//����Ĵ���
	__asm
	{
		pushad
		pushfd
	}

	//pushad�ᱣ��8��4�ֽڵļĴ���32
	//pushfd�ᱣ��4���ֽڵ�EFLAGS
	//�������������ջ֮ǰ���д�����滻����ֻ��ͨ��ESP���Ҳ���
	//���û��pushad��pushfd������һΪ ESP+4��������Ϊ ESP+8
	//����һΪ ESP + 0x28��32 + 4 + 4��
	//������Ϊ EBP + 0x2c (32 + 4 + 8��
	//����������������ջ֮����д�����滻�����������ҿ�����EBP���Ҳ���
	//����һΪ EBP + 0x8
	//������Ϊ EBP + 0xc

	__asm
	{
		mov EAX, dword ptr[EBP + 0x8]
		mov x, EAX
		mov EAX, dword ptr[EBP + 0xc]
		mov y, EAX
	}

	_stprintf_s(szBuffer, MAX_PATH, TEXT("��ȡ���� %d - %d"), x, y);
	MessageBox(NULL, szBuffer, TEXT("��ȡ����"), MB_OK);

	//�ָ��Ĵ���
	__asm
	{
		popfd
		popad
	}

	//ִ��֮ǰ�滻�Ĵ���
	__asm
	{
		mov eax, 0CCCCCCCCh
	}

	//����ԭ���ĵط�
	__asm
	{
		jmp oldJmp
	}
}

int add(int x, int y)
{
	return x + y;
}

int main()
{
	HANDLE hProcess = GetCurrentProcess();

	LPVOID oldData = NULL;

	//Ϊʲôoffset��16���ֽڣ���Ϊ�ҿ�ʼ�滻��λ����mov eax, 0CCCCCCCCh��䣬������ƫ�Ƹպ�16�ֽ�
	//00412A70 55                   push        ebp  
	//00412A71 8B EC                mov         ebp, esp
	//00412A73 81 EC C0 00 00 00    sub         esp, 0C0h
	//00412A79 53                   push        ebx
	//00412A7A 56                   push        esi
	//00412A7B 57                   push        edi
	//00412A7C 8B FD                mov         edi, ebp
	//00412A7E 33 C9				xor			ecx, ecx
	//00412A80 B8 CC CC CC CC       mov         eax, 0CCCCCCCCh
	installInlineHook(hProcess, addAddress, (DWORD)myAdd, 16, 5, &oldData);

	int ret = add(2, 3);

	printf("%d\n", ret);

	unInstallInlineHook(hProcess, addAddress, 16, 5, oldData);

	ret = add(5, 6);

	printf("%d\n", ret);

	return 0;
}