#include <windows.h>
#include <stdio.h>
#include <tchar.h>

//测试时，请把随机基址关了，开启固定基址

//这里是我测试时add函数的地址，需要改成你们自已的
//直接拿函数名来当地址，因为在VS中，函数会转一道，就是JMP一下才会是真正的函数地址，直接拿函数名当地址会有问题
DWORD addAddress = 0x00412A70;
DWORD oldJmp = addAddress + 16 + 5;
DWORD x = 0;
DWORD y = 0;
TCHAR szBuffer[MAX_PATH]{ 0 };

int installInlineHook(HANDLE hProcess, DWORD oldFunc, DWORD newFunc, DWORD offset, DWORD size, LPVOID* oldData)
{
	if (size < 5)
	{
		printf("跳转最少占用5个字节，不能小于5个字节\n");
		return -1;
	}

	//计算开始地址
	DWORD start = oldFunc + offset;

	//申请内存，用于保存替换的数据
	LPBYTE oldBuf = (LPBYTE)malloc(size);
	memset(oldBuf, 0, size);
	ReadProcessMemory(hProcess, (LPCVOID)(start), oldBuf, size, NULL);

	//假设我们需要获得E9 后面的硬编码为X
	//X = 真正要跳转的地址 - E9这条指令的下一行地址
	//E9这条指令的下一行地址 = 当前地址 + 5
	//X = 真正要跳转的地址 - 当前地址 - 5
	DWORD address = newFunc - start - 5;

	// 开启写权限
	DWORD oldProtected;
	VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtected);

	//替换原先的硬编码
	*(LPBYTE)start = 0xE9;
	*(LPDWORD)((LPBYTE)start + 1) = address;

	// 关闭写保护
	VirtualProtect((LPVOID)start, size, oldProtected, &oldProtected);

	*oldData = oldBuf;

	return 0;
}

VOID unInstallInlineHook(HANDLE hProcess, DWORD oldFunc, DWORD offset, DWORD size, LPVOID oldData)
{
	//计算开始地址
	DWORD start = oldFunc + offset;

	// 开启写权限
	DWORD oldProtected;
	VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtected);

	//替换原先的硬编码
	WriteProcessMemory(hProcess, (LPVOID)start, oldData, size, NULL);

	// 关闭写保护
	VirtualProtect((LPVOID)start, size, oldProtected, &oldProtected);
}

extern "C" __declspec(naked) void myAdd()
{
	//保存寄存器
	__asm
	{
		pushad
		pushfd
	}

	//pushad会保存8个4字节的寄存器32
	//pushfd会保存4个字节的EFLAGS
	//如果你是在提升栈之前进行代码的替换，那只能通过ESP来找参数
	//如果没有pushad和pushfd，参数一为 ESP+4，参数二为 ESP+8
	//参数一为 ESP + 0x28（32 + 4 + 4）
	//参数二为 EBP + 0x2c (32 + 4 + 8）
	//由于我是在提升堆栈之后进行代码的替换，所以这里我可以用EBP来找参数
	//参数一为 EBP + 0x8
	//参数二为 EBP + 0xc

	__asm
	{
		mov EAX, dword ptr[EBP + 0x8]
		mov x, EAX
		mov EAX, dword ptr[EBP + 0xc]
		mov y, EAX
	}

	_stprintf_s(szBuffer, MAX_PATH, TEXT("获取参数 %d - %d"), x, y);
	MessageBox(NULL, szBuffer, TEXT("获取参数"), MB_OK);

	//恢复寄存器
	__asm
	{
		popfd
		popad
	}

	//执行之前替换的代码
	__asm
	{
		mov eax, 0CCCCCCCCh
	}

	//跳回原来的地方
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

	//为什么offset是16个字节，因为我开始替换的位置是mov eax, 0CCCCCCCCh这句，到这句的偏移刚好16字节
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