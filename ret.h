void unprotect_func(DWORD Address, int RetNum) /*address of function you are attempting to call without triggering the return-address checker*/
{
	DWORD Function = Address;
	for (int i = 0; i < RetNum; Function++)
	{
		char gOpCode = *(char*)Function;
		if (gOpCode == 0x72) /* checks if instruction at given address is a JB (opcode 0x72) */
		{
			char gOpCode2 = *(char*)(Function + 0x12); 
			if (gOpCode2 == 0x72)
			{
				WriteProcessMemory(GetCurrentProcess(), *(LPVOID*)&Function, "\xEB", 1, NULL); /* patch the JB instruction into a JMP (opcode 0xEB) */
				i++;
			}
		}
	}
}

/* the protect function below reverts the changes made so the integrity checker doesn't detect any changes made to memory. for this to work the changes
need to be restored within 200ms */
void Protect(DWORD Address, int RetNum) 
{
	DWORD Function = Address;
	for (int i = 0; i < RetNum; Function++)
	{
		char gOpCode = *(char*)Function;
		if (gOpCode == 0xEB) /* checks if the instruction at the given address is a jmp */
		{
			char gOpCode2 = *(char*)(Function + 0x12);
			if (gOpCode2 == 0xEB)
			{
				WriteProcessMemory(GetCurrentProcess(), *(LPVOID*)&Function, "\x72", 1, NULL);
				i++;
			}
		}
	}
}
