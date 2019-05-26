#include "stdafx.h"

extern "C" int DetoursInitZydis32();
extern "C" int DetoursInitZydis64();
extern "C" int DetoursGetNextInstructionLength(void *Instruction);

#ifdef _M_IX86
namespace Detours
{
	namespace X86
	{
		#define HEADER_MAGIC		'@D32'

		#define MAX_INSTRUCT_SIZE	0x08

		#define JUMP_LENGTH_32		0x05	// jmp <addr>
		#define CALL_LENGTH_32		0x05	// call <addr>
		#define JUMP_EAX_LENGTH_32	0x07	// mov eax, <addr>; jmp eax
		#define JUMP_PTR_LENGTH_32	0x06	// jmp dword ptr <addr>
		#define PUSH_RET_LENGTH_32	0x06	// push <addr>; retn

		#define ALIGN_32(x)			DetourAlignAddress((uint64_t)(x), 0x4);
		#define BREAK_ON_ERROR()	{ if (GetGlobalOptions() & OPT_BREAK_ON_FAIL) __debugbreak(); }

		uint8_t *DetourFunction(uint8_t *Target, uint8_t *Detour, X86Option Options)
		{
			if (!Target || !Detour)
			{
				BREAK_ON_ERROR();
				return nullptr;
			}

			// Init decoder exactly once
			static bool decoderInit = []()
			{
				return DetoursInitZydis32() == -1 ? false : true;
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
			allocSize += MAX_INSTRUCT_SIZE;				// Maximum instruction size
			allocSize += MAX_INSTRUCT_SIZE;				// Maximum instruction size
			allocSize += 0x64;							// Padding for any memory alignment

			uint8_t *jumpTrampolinePtr = (uint8_t *)VirtualAlloc(nullptr, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

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
			header->InstructionOffset	= (sizeptr_t)ALIGN_32(jumpTrampolinePtr + sizeof(JumpTrampolineHeader));

			header->TrampolineLength	= JUMP_LENGTH_32;
			header->TrampolineOffset	= (sizeptr_t)ALIGN_32(header->InstructionOffset + header->InstructionLength + JUMP_LENGTH_32 + header->TrampolineLength);

			// Copy the old instructions over
			DetourCopyMemory(header->InstructionOffset, header->CodeOffset, header->InstructionLength);

			// Write the assembly in the allocation block
			DetourWriteStub(header);

			bool result = true;

			switch (Options)
			{
			case X86Option::USE_JUMP:		result = DetourWriteJump(header);		break;
			case X86Option::USE_CALL:		result = DetourWriteCall(header);		break;
			case X86Option::USE_PUSH_RET:	result = DetourWritePushRet(header);	break;
			default:						result = false;							break;
			}

			// If an operation failed free the memory and exit
			if (!result)
			{
				VirtualFree(jumpTrampolinePtr, 0, MEM_RELEASE);

				BREAK_ON_ERROR();
				return nullptr;
			}

			// Set read/execution on the page & flush any cache
			DWORD dwOld = 0;
			VirtualProtect(jumpTrampolinePtr, allocSize, PAGE_EXECUTE_READ, &dwOld);

			DetourFlushCache((sizeptr_t)Target, totalInstrSize);
			DetourFlushCache((sizeptr_t)jumpTrampolinePtr, allocSize);

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
			uint8_t *virtualPointer = (Target + (TableIndex * sizeof(ULONG)));

			DWORD dwOld = 0;
			if (!VirtualProtect(virtualPointer, sizeof(ULONG), PAGE_EXECUTE_READWRITE, &dwOld))
			{
				BREAK_ON_ERROR();
				return nullptr;
			}

			uint8_t *original = (uint8_t *)InterlockedExchange((volatile ULONG *)virtualPointer, (ULONG)Detour);

			VirtualProtect(virtualPointer, sizeof(ULONG), dwOld, &dwOld);

			return original;
		}

		bool VTableRemove(uint8_t *Target, uint8_t *Function, uint32_t TableIndex)
		{
			// Reverse VTable detour
			return DetourVTable(Target, Function, TableIndex) != nullptr;
		}

		void DetourWriteStub(JumpTrampolineHeader *Header)
		{
			/********** Allocated code block modifications **********/
			uint8_t buffer[5];
			
			sizeptr_t unhookStart = (Header->CodeOffset + Header->InstructionLength);		// Determine where the 'unhooked' part of the function starts
			sizeptr_t binstrPtr = (Header->InstructionOffset + Header->InstructionLength);	// Jump to hooked function (Backed up instructions)

			buffer[0] = 0xE9;
			*(int32_t *)&buffer[1] = (int32_t)(unhookStart - (binstrPtr + 5));

			memcpy((void *)binstrPtr, &buffer, sizeof(buffer));

			// Jump to user function (Write the trampoline)
			buffer[0] = 0xE9;
			*(int32_t *)&buffer[1] = (int32_t)(Header->DetourOffset - (Header->TrampolineOffset + 5));

			memcpy((void *)Header->TrampolineOffset, &buffer, sizeof(buffer));
		}

		bool DetourWriteJump(JumpTrampolineHeader *Header)
		{
			// Relative JUMP
			uint8_t buffer[5];

			buffer[0] = 0xE9;
			*(int32_t *)&buffer[1] = (int32_t)(Header->TrampolineOffset - (Header->CodeOffset + 5));

			return DetourCopyMemory(Header->CodeOffset, (sizeptr_t)&buffer, sizeof(buffer));
		}

		bool DetourWriteCall(JumpTrampolineHeader *Header)
		{
			// Relative CALL
			uint8_t buffer[5];

			buffer[0] = 0xE8;
			*(int32_t *)&buffer[1] = (int32_t)(Header->TrampolineOffset - (Header->CodeOffset + 5));

			return DetourCopyMemory(Header->CodeOffset, (sizeptr_t)&buffer, sizeof(buffer));
		}

		bool DetourWritePushRet(JumpTrampolineHeader *Header)
		{
			// RET-Jump to trampoline
			uint8_t buffer[6];

			// push 0xXXXXX
			buffer[0] = 0x68;
			*(uint32_t *)&buffer[1] = Header->TrampolineOffset;

			// retn
			buffer[5] = 0xC3;

			return DetourCopyMemory(Header->CodeOffset, (sizeptr_t)&buffer, sizeof(buffer));
		}

		uint32_t DetourGetHookLength(X86Option Options)
		{
			uint32_t size = 0;

			switch (Options)
			{
			case X86Option::USE_JUMP:		size += JUMP_LENGTH_32;		break;
			case X86Option::USE_CALL:		size += CALL_LENGTH_32;		break;
			case X86Option::USE_PUSH_RET:	size += PUSH_RET_LENGTH_32;	break;
			default:						size = 0;					break;
			}

			return size;
		}
	}
}
#endif // _M_IX86