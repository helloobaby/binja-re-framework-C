#pragma once
#include "binaryninjaapi.h"

using namespace BinaryNinja;
extern BinaryView* g_bv;

// BinaryNinja弹出一个窗口,让用户输入一个地址,该函数返回这个输入
// 如果输入的不是一个地址,该函数返回0
uint64_t UtilsGetAddressInput();

// 获得某一个地址对应的LowLevelILInstruction
std::optional<LowLevelILInstruction> UtilsGetLowLevelIlAt(uint64_t Addr);

// 获得一个地址的反汇编
std::vector<InstructionTextToken> UtilsGetDisassemblyTextAt(uint64_t Addr);

std::string hex(DataBuffer Buffer);

void UtilsShowTraceStack(char* szBriefInfo /*= NULL*/);

std::string UtilsGetJmpType(uint64_t BaseAddress,uint64_t DestAddress);

bool UtilsDumpLowlevelIl(const LowLevelILInstruction& instr);