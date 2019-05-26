#include "stdafx.h"

extern "C" int DetoursInitZydis32();
extern "C" int DetoursInitZydis64();
extern "C" int DetoursGetNextInstructionLength(void *Instruction);

#ifdef _M_AMD64
namespace Detours
{
	namespace X64
	{
		#define HEADER_MAGIC		'@D64'

		#define MAX_INSTRUCT_SIZE	0x20

		#define PUSH_RET_LENGTH_64	0x0E	// push <low 32 addr>; mov [rsp+4h], <hi 32 addr>; ret;
		#define RAX_JUMP_64			0x0C	// mov rax, <addr>; jmp rax;
		#define REL32_JUMP_64		0x05	// jmp <address within +/- 2GB>

		#define ALIGN_64(x)			DetourAlignAddress((uint64_t)(x), 0x10);
		#define BREAK_ON_ERROR()	{ if (GetGlobalOptions() & OPT_BREAK_ON_FAIL) __debugbreak(); }

		uint8_t *DetourFunction(uint8_t *Target, uint8_t *Detour, X64Option Options)
		{
			if (!Target || !Detour)
			{
				BREAK_ON_ERROR();
				return nullptr;
			}

			// Init decoder exactly once
			static bool decoderInit = []()
			{
				return DetoursInitZydis64() == -1 ? false : true;
			}();

			if (!decoderInit)
			{
				BREAK_ON_ERROR();
				return nullptr;
			}

			// Decode the actual assembly
			uint32_t neededSize = DetourGetHookLength(Options);
			uint32_t totalInstrSize = 0;

			for (int len = 0; len != -1; len = DetoursGetNextInstructionLength((void *)(Target + totalInstrSize)))
			{
				totalInstrSize += len;

				if (totalInstrSize >= neededSize)
					break;
			}

			// Unable to find a needed length
			if (neededSize == 0 || totalInstrSize < neededSize)
			{
				BREAK_ON_ERROR();
				return nullptr;
			}

			// Allocate the trampoline data
			uint32_t allocSize = 0;
			allocSize += sizeof(JumpTrampolineHeader);	// Base structure
			allocSize += totalInstrSize;				// Size of the copied instructions
			allocSize += MAX_INSTRUCT_SIZE;				// For DetourWriteStub
			allocSize += MAX_INSTRUCT_SIZE;				// For DetourWriteStub
			allocSize += 0x64;							// Padding for any memory alignment

			uint8_t *jumpTrampolinePtr = nullptr;
			
			// NOTE: If we're doing a REL32 hook, we need to do some magic
			if (Options == X64Option::USE_REL32_JUMP)
			{
				// Find a region within 2GB (subtract some for tolerance)
				sizeptr_t maxDelta	= (1ull * 1024 * 1024 * 1024) - 4096;

				sizeptr_t start = ((sizeptr_t)Target - maxDelta);
				sizeptr_t end	= ((sizeptr_t)Target + maxDelta);

				while (start < end)
				{
					MEMORY_BASIC_INFORMATION memInfo;
					if (VirtualQuery((LPVOID)start, &memInfo, sizeof(memInfo)) == 0)
						break;

					if (memInfo.State == MEM_FREE && memInfo.RegionSize >= allocSize)
					{
						jumpTrampolinePtr = (uint8_t *)VirtualAlloc(memInfo.BaseAddress, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

						if (jumpTrampolinePtr)
							break;
					}

					start = (sizeptr_t)memInfo.BaseAddress + 4096 + 1;
				}
			}
			else
			{
				// Can be allocated anywhere
				jumpTrampolinePtr = (uint8_t *)VirtualAlloc(nullptr, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			}

			if (!jumpTrampolinePtr)
			{
				BREAK_ON_ERROR();
				return nullptr;
			}

			// Fill out the header
			JumpTrampolineHeader *header = (JumpTrampolineHeader *)jumpTrampolinePtr;

			header->Magic				= HEADER_MAGIC;
			header->Random				= GetCurrentProcessId() + GetCurrentThreadId() + totalInstrSize;

			header->CodeOffset			= (sizeptr_t)Target;
			header->DetourOffset		= (sizeptr_t)Detour;

			header->InstructionLength	= totalInstrSize;
			header->InstructionOffset	= ALIGN_64(jumpTrampolinePtr + sizeof(JumpTrampolineHeader));

			header->TrampolineLength	= MAX_INSTRUCT_SIZE;
			header->TrampolineOffset	= ALIGN_64(header->InstructionOffset + header->InstructionLength + MAX_INSTRUCT_SIZE + header->TrampolineLength);

			// Copy the old instructions over
			DetourCopyMemory(header->InstructionOffset, header->CodeOffset, header->InstructionLength);

			// Write the assembly in the allocation block
			DetourWriteStub(header);

			bool result = true;

			switch (Options)
			{
			case X64Option::USE_PUSH_RET:	result = DetourWritePushRet(header);	break;
			case X64Option::USE_RAX_JUMP:	result = DetourWriteRaxJump(header);	break;
			case X64Option::USE_REL32_JUMP:	result = DetourWriteRel32Jump(header);	break;
			default:						result = false;							break;
			}

			if (!result)
			{
				VirtualFree(jumpTrampolinePtr, 0, MEM_RELEASE);

				BREAK_ON_ERROR();
				return nullptr;
			}

			// Force flush any possible CPU cache
			DetourFlushCache((sizeptr_t)Target, totalInstrSize);
			DetourFlushCache((sizeptr_t)jumpTrampolinePtr, allocSize);

			// Set read/execution on the page
			DWORD dwOld = 0;
			VirtualProtect(jumpTrampolinePtr, allocSize, PAGE_EXECUTE_READ, &dwOld);

			return (uint8_t *)header->InstructionOffset;
		}

		bool DetourRemove(uint8_t *Trampoline)
		{
			if (!Trampoline)
			{
				BREAK_ON_ERROR();
				return false;
			}

			JumpTrampolineHeader *header = (JumpTrampolineHeader *)(Trampoline - sizeof(JumpTrampolineHeader));

			if (header->Magic != HEADER_MAGIC)
			{
				BREAK_ON_ERROR();
				return false;
			}

			// Rewrite the backed-up code
			if (!DetourCopyMemory(header->CodeOffset, header->InstructionOffset, header->InstructionLength))
			{
				BREAK_ON_ERROR();
				return false;
			}

			DetourFlushCache(header->CodeOffset, header->InstructionLength);
			VirtualFree(header, 0, MEM_RELEASE);

			return true;
		}

		uint8_t *DetourVTable(uint8_t *Target, uint8_t *Detour, uint32_t TableIndex)
		{
			// Each function is stored in an array
			uint8_t *virtualPointer = (Target + (TableIndex * sizeof(ULONG64)));

			DWORD dwOld = 0;
			if (!VirtualProtect(virtualPointer, sizeof(ULONG64), PAGE_EXECUTE_READWRITE, &dwOld))
				return nullptr;

			uint8_t *original = (uint8_t *)InterlockedExchange64((volatile LONG64 *)virtualPointer, (LONG64)Detour);

			VirtualProtect(virtualPointer, sizeof(LONG64), dwOld, &dwOld);
			return original;
		}

		bool VTableRemove(uint8_t *Target, uint8_t *Function, uint32_t TableIndex)
		{
			// Reverse VTable detour
			return DetourVTable(Target, Function, TableIndex) != nullptr;
		}

		void DetourWriteStub(JumpTrampolineHeader *Header)
		{
			auto writeJmp = [](sizeptr_t Base, sizeptr_t Destination)
			{
				uint8_t buffer[14];

				// 'jmp qword ptr [rip + 0x6]' - unaligned
				buffer[0] = 0xFF;
				buffer[1] = 0x25;
				*(uint32_t *)&buffer[2] = 0x0;
				*(uint64_t *)&buffer[6] = Destination;

				return DetourCopyMemory(Base, (sizeptr_t)&buffer, sizeof(buffer));
			};

			// Jump to hooked function (Backed up instructions) [UserFunction -> OldInstructions -> THIS -> HookedFunction]
			uintptr_t unhookStart	= (Header->CodeOffset + Header->InstructionLength);
			uintptr_t instr_ptr		= (Header->InstructionOffset + Header->InstructionLength);
			writeJmp(instr_ptr, unhookStart);

			// Jump to user function (Write the trampoline) [HookedFunction -> THIS -> UserFunction]
			writeJmp(Header->TrampolineOffset, Header->DetourOffset);
		}

		bool DetourWritePushRet(JumpTrampolineHeader *Header)
		{
			uint8_t buffer[14];

			// Jump with PUSH/RET (push low32, [rsp+4h] = hi32)
			//
			// push dword low32
			// mov dword [rsp + 0x4], hi32
			// ret
			//
			buffer[0] = 0x68;
			*(uint32_t *)&buffer[1] = (uint32_t)(Header->TrampolineOffset & 0xFFFFFFFF);
			buffer[5] = 0xC7;
			buffer[6] = 0x44;
			buffer[7] = 0x24;
			buffer[8] = 0x04;
			*(uint32_t *)&buffer[9] = (uint32_t)(Header->TrampolineOffset >> 32);
			buffer[13] = 0x04;

			return DetourCopyMemory(Header->CodeOffset, (sizeptr_t)&buffer, sizeof(buffer));
		}

		bool DetourWriteRaxJump(JumpTrampolineHeader *Header)
		{
			// Jump to trampoline (from hooked function)
			//
			// mov rax, offset64
			// jmp rax
			//
			uint8_t buffer[12];
			buffer[0] = 0x48;
			buffer[1] = 0xB8;
			*(uint64_t *)&buffer[2] = Header->TrampolineOffset;

			buffer[10] = 0xFF;
			buffer[11] = 0xE0;

			return DetourCopyMemory(Header->CodeOffset, (sizeptr_t)&buffer, sizeof(buffer));
		}

		bool DetourWriteRel32Jump(JumpTrampolineHeader *Header)
		{
			// Assumes that the delta is less than 2GB. We need to manually write the offset.
			//
			// jmp offset64
			//
			int64_t displacement = (int64_t)(Header->TrampolineOffset - (Header->CodeOffset + 5));

			if (abs(displacement) >= INT_MAX)
				return false;

			uint8_t buffer[5];
			buffer[0] = 0xE9;
			*(int32_t *)&buffer[1] = (int32_t)displacement;

			return DetourCopyMemory(Header->CodeOffset, (sizeptr_t)&buffer, sizeof(buffer));
		}

		uint32_t DetourGetHookLength(X64Option Options)
		{
			uint32_t size = 0;

			switch(Options)
			{
			case X64Option::USE_PUSH_RET:	size += PUSH_RET_LENGTH_64;	break;
			case X64Option::USE_RAX_JUMP:	size += RAX_JUMP_64;		break;
			case X64Option::USE_REL32_JUMP:	size += REL32_JUMP_64;		break;
			default:						size = 0;					break;
			}

			return size;
		}
	}
}
#endif // _M_AMD64