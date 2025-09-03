#pragma once
#include "binaryninjaapi.h"

using namespace BinaryNinja;
extern BinaryView* g_bv;

// BinaryNinja����һ������,���û�����һ����ַ,�ú��������������
// �������Ĳ���һ����ַ,�ú�������0
uint64_t UtilsGetAddressInput();

// ���ĳһ����ַ��Ӧ��LowLevelILInstruction
std::optional<LowLevelILInstruction> UtilsGetLowLevelIlAt(uint64_t Addr);

// ���һ����ַ�ķ����TextTokens
std::vector<InstructionTextToken> UtilsGetDisassemblyTextAt(uint64_t Addr);

// �ַ�����ӡʮ����������
std::string hex(DataBuffer Buffer);

void UtilsShowTraceStack(char* szBriefInfo /*= NULL*/);

// ��Ҫ�����ö���ת������Patch��Ҫʹ�õ��ֽ���
// "short" �� "near"
std::string UtilsGetJmpType(uint64_t BaseAddress,uint64_t DestAddress);

// ��ӡLowlevel IL,������������
void UtilsDumpLowlevelIl(const LowLevelILInstruction& instr, int depth);

// Example Usage: 
// EasyRegisterWrapper(Run, "Run", { 0x401000 });
using DebugFuncList = std::vector<uint64_t>;
void EasyRegisterWrapper(std::function<void(const DebugFuncList&)> f,
	const std::string& name,
	DebugFuncList funcs);