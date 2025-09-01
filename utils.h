#pragma once
#include "binaryninjaapi.h"

using namespace BinaryNinja;
extern BinaryView* g_bv;

// BinaryNinja弹出一个窗口,让用户输入一个地址,该函数返回这个输入
// 如果输入的不是一个地址,该函数返回0
uint64_t UtilsGetAddressInput();

// 获得某一个地址对应的LowLevelILInstruction
std::optional<LowLevelILInstruction> UtilsGetLowLevelIlAt(uint64_t Addr);

// 获得一个地址的反汇编TextTokens
std::vector<InstructionTextToken> UtilsGetDisassemblyTextAt(uint64_t Addr);

// 字符串打印十六进制序列
std::string hex(DataBuffer Buffer);

void UtilsShowTraceStack(char* szBriefInfo /*= NULL*/);

// 主要是利用短跳转来减少Patch需要使用的字节数
// "short" 或 "near"
std::string UtilsGetJmpType(uint64_t BaseAddress,uint64_t DestAddress);

// 打印Lowlevel IL,用来辅助调试
void UtilsDumpLowlevelIl(const LowLevelILInstruction& instr, int depth);

// Example Usage: 
// EasyRegisterWrapper(Solve_All, "Solve_All", {  });
void EasyRegisterWrapper(std::function<void(std::vector<uint64_t> DebugFunctionList)> f, std::string name, std::vector<uint64_t> DebugFunctionList);