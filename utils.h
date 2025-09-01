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
// EasyRegisterWrapper(Solve_All, "Solve_All", {  });
void EasyRegisterWrapper(std::function<void(std::vector<uint64_t> DebugFunctionList)> f, std::string name, std::vector<uint64_t> DebugFunctionList);