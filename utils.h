#pragma once
#include "binaryninjaapi.h"

using namespace BinaryNinja;
extern BinaryView* g_bv;

// BinaryNinja����һ������,���û�����һ����ַ,�ú��������������
// �������Ĳ���һ����ַ,�ú�������0
uint64_t UtilsGetAddressInput();

// ���ĳһ����ַ��Ӧ��LowLevelILInstruction
std::optional<LowLevelILInstruction> UtilsGetLowLevelIlAt(uint64_t Addr);

// ���һ����ַ�ķ����
std::vector<InstructionTextToken> UtilsGetDisassemblyTextAt(uint64_t Addr);

std::string hex(DataBuffer Buffer);

void UtilsShowTraceStack(char* szBriefInfo /*= NULL*/);

std::string UtilsGetJmpType(uint64_t BaseAddress,uint64_t DestAddress);

bool UtilsDumpLowlevelIl(const LowLevelILInstruction& instr);