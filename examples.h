#pragma once
#include "core.h"
#include "binaryninjaapi.h"
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include "utils.h"
#include "include/magic_enum/magic_enum.hpp"
#include <exception>
#include <dbghelp.h>
using namespace BinaryNinja;
extern BinaryView* g_bv;

//10001096  e800000000         call    $ + 5  {data_1000109b}
//1000109b  5f                 pop     edi						-> mov edi,0x1000109b
void Solve_CallPop() {
	for (auto Func : g_bv->GetAnalysisFunctionList()) {
		LogInfo("[Solve_CallPop] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		Func->SetAnalysisSkipOverride(NeverSkipFunctionAnalysis);
		// https://github.com/Vector35/binaryninja-api/issues/5124
		//g_bv->UpdateAnalysisAndWait();
		auto BBList = Func->GetBasicBlocks();
		for (const auto& BB : BBList) {
			const auto& DisTokenList = BB->GetDisassemblyText(new DisassemblySettings());
			for (int i = 0; i < DisTokenList.size(); i++) {
				if (i == (DisTokenList.size() - 1))
					break;
				auto Opcodes = g_bv->ReadBuffer(DisTokenList[i].addr, g_bv->GetInstructionLength(g_bv->GetDefaultArchitecture(), DisTokenList[i].addr));
				// call $+5
				if (Opcodes.GetLength() == 5 && Opcodes[0] == 0xe8 && Opcodes[1] == 0) {
					auto NextInstructionTokens = UtilsGetDisassemblyTextAt(DisTokenList[i + 1].addr);
					if (NextInstructionTokens.size() > 1 && NextInstructionTokens[1].text == "pop") {
						// 利用模式匹配找到这种地址 
						LogInfo("[Solve_CallPop] %llx", DisTokenList[i].addr);
						std::string reg = NextInstructionTokens[3].text;
						// Nop这两条指令
						g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), DisTokenList[i].addr);
						g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), DisTokenList[i+1].addr);

						std::string error;
						DataBuffer Buf;
						if (g_bv->GetDefaultArchitecture()->Assemble(fmt::format("mov {},{:#x}", reg, DisTokenList[i + 1].addr), 0, Buf, error)) {
							LogInfo("[Solve_CallPop] %s", hex(Buf).c_str());
							g_bv->WriteBuffer(DisTokenList[i].addr, Buf);
						}
						else {
							LogError("[Solve_CallPop] Error 1 , {:#x}", DisTokenList[i].addr);
						}
					}
				}
			}
		}
		//break;
	}
}

//1000255d  push    edi {var_8}
//1000255e  retn    反编译看到ret直接认为函数到末尾停止分析了,需要Patch成为Jmp
void Solve_Push_Ret() {
	for (auto Func : g_bv->GetAnalysisFunctionList()) {
		LogInfo("[Solve_Push_Ret] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		auto BBList = Func->GetBasicBlocks();
		for (const auto& BB : BBList) {
			const auto& DisTokenList = BB->GetDisassemblyText(new DisassemblySettings());
			for (int i = 0; i < DisTokenList.size(); i++) {
				if (i == (DisTokenList.size() - 1))
					continue;
				if (BB->GetDisassemblyText(new DisassemblySettings()).size() < 2)
					continue;
				uint64_t TerminatorAddr = BB->GetDisassemblyText(new DisassemblySettings()).back().addr;
				DataBuffer Buf = g_bv->ReadBuffer(TerminatorAddr, 1);
				// ret
				if (Buf[0] == 0xC3 ) {
					auto addr = BB->GetDisassemblyText(new DisassemblySettings())[BB->GetDisassemblyText(new DisassemblySettings()).size() - 2].addr;
					DataBuffer Opcode = g_bv->ReadBuffer(addr, 1);
					if (Opcode[0] >= 0x50 && Opcode[0] <= 0x57) {
						LogInfo("[Solve_Push_Ret] Get %llx", addr);
						auto reg = BB->GetDisassemblyText(new DisassemblySettings())[BB->GetDisassemblyText(new DisassemblySettings()).size() - 2].tokens[3].text;
						std::string error;
						DataBuffer Buf;
						g_bv->GetDefaultArchitecture()->Assemble(fmt::format("jmp {}", reg), 0, Buf, error);
						if (Buf.GetLength() == 2) {
							g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), addr);
							g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), addr + 1);
							g_bv->WriteBuffer(addr, Buf);
							// 迭代下一个BasicBlock
							continue;
						}
					}
				}
			}
		}
	}
}
template<typename T>
T simplifyAddInst(T a,T b) {
	return a+b;
}
template<typename T>
T simplifySubInst(T a, T b) {
	return a - b;
}
template<typename T>
T simplifyXorInst(T a, T b) {
	return a ^ b;
}
template<typename T>
T simplifyMulInst(T a, T b) {
	return a * b;
}
template<typename T>
T simplifyNotInst(T n) {
	return (~n);
}
template<typename T>
T simplifyAndInst(T a, T b) {
	return a & b;
}

template<typename T>
T simplifyBinOp(BNMediumLevelILOperation Operation, T a, T b) {
	switch (Operation)
	{
		if (b) {
	case MLIL_ADD:
		return simplifyAddInst<T>(a, b);
	case MLIL_SUB:
		return simplifySubInst<T>(a, b);
	case MLIL_XOR:
		return simplifyXorInst<T>(a, b);
	case MLIL_MUL:
		return simplifyMulInst<T>(a, b);
	case MLIL_AND:
		return simplifyAndInst<T>(a, b);
	default:
		throw std::runtime_error(fmt::format("Unhandle Operation {}", magic_enum::enum_name(Operation)).data());
		}
	}
}


// 简单的数据流分析算法,判断一个SSA变量是否是常量
template <typename T>
std::optional<T> get_possiable_value(Ref<MediumLevelILFunction> Func, const MediumLevelILInstruction &Var) {
	
	LogDebug("[%s] Get operation %s", __FUNCTION__, magic_enum::enum_name(Var.operation).data());
	if (Var.operation == MLIL_CONST_PTR || Var.operation == MLIL_CONST) {
		auto Constant = Var.GetConstant();
		LogDebug("[%s] Get Constant %llx",__FUNCTION__, Constant);
		return Var.GetConstant();
	}

	//https://github.com/Vector35/binaryninja-api/blob/17158e9942a73327f176ef642a1cafcaf8cb7b03/mediumlevelilinstruction.h#L1097
	if (Var.operation == MLIL_VAR_SSA || Var.operation == MLIL_VAR_ALIASED) {
		auto index_ssa_def = Func->GetSSAVarDefinition(Var.GetSourceSSAVariable());
		if (index_ssa_def > Func->GetInstructionCount()) {
			LogDebug("[%s] index_ssa_def %d invalid", __FUNCTION__, index_ssa_def);
			return std::nullopt;
		}
		auto ssa_def = Func->GetInstruction(index_ssa_def);

		// Op必须是赋值
		if (ssa_def.operation != MLIL_SET_VAR_SSA && ssa_def.operation == MLIL_SET_VAR_ALIASED) {
			LogDebug("[%s] ssa_def.operation %s invalid ", __FUNCTION__, magic_enum::enum_name(ssa_def.operation).data());
			return std::nullopt;
		}
		auto source = ssa_def.GetSourceExpr();
		auto source_operation = source.operation;

		LogDebug("[%s] ssa_def %s operation %s , source_operation %s", __FUNCTION__, ssa_def.Dump(), magic_enum::enum_name(ssa_def.operation).data(), magic_enum::enum_name(source_operation).data());

		// 从堆栈中读取
		if (source_operation == MLIL_LOAD_SSA) {

		}

		if (source_operation != MLIL_ADD && source_operation != MLIL_SUB && source_operation != MLIL_XOR && source_operation != MLIL_MUL && source_operation != MLIL_AND
			&& source_operation != MLIL_VAR_SSA && source_operation != MLIL_VAR_ALIASED) {
			LogDebug("[%s] source_operation %s invalid", __FUNCTION__, magic_enum::enum_name(source_operation).data());
			return std::nullopt;
		}
		auto op_count = source.GetOperands().size();
		LogDebug("[%s] op_count %d", __FUNCTION__, op_count);
		if (op_count == 1) {
			return get_possiable_value<T>(Func,source.GetRawOperandAsExpr(0));
		}
		else if (op_count == 2) {
			auto left = get_possiable_value<T>(Func, source.GetRawOperandAsExpr(0));
			auto right = get_possiable_value<T>(Func, source.GetRawOperandAsExpr(1));
			if (left && right) {
				return simplifyBinOp<T>(source.operation, *left, *right);
			}
		}
		else
			return std::nullopt;
	}

	return std::nullopt;
}

// 利用BinaryNinja的数据流分析做优化
void Solve_Jmp_ConstantPtr() {
	for (auto Func : g_bv->GetAnalysisFunctionList()) {
		LogInfo("[Solve_Jmp_ConstantPtr] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		Func->SetAnalysisSkipOverride(NeverSkipFunctionAnalysis);
		auto LFunc = Func->GetLowLevelIL();
		if (!LFunc) // 有时候LFunc是非法的,下面获取BasicBlock直接崩溃
			continue;
		auto BBList = LFunc->GetBasicBlocks();

		for (const auto& BB : BBList) {
			auto llil = UtilsGetLowLevelIlAt(BB->GetDisassemblyText(new DisassemblySettings()).back().addr);
			if (!llil)
				continue;
			if (llil->operation == LLIL_JUMP_TO) {
				auto OutEdges = BB->GetOutgoingEdges();
				if (OutEdges.size()) {
					LogInfo("[Solve_Jmp_ConstantPtr] Get %llx", BB->GetDisassemblyText(new DisassemblySettings()).back().addr);
					// 跳转到常量地址
					auto Start = LFunc->GetInstruction(OutEdges[0].target->GetStart()).address;;
					LogInfo("[Solve_Jmp_ConstantPtr] OutEdges.Target %llx", Start);

					auto OriginJmpInstrtionSize = g_bv->GetInstructionLength(g_bv->GetDefaultArchitecture(), BB->GetDisassemblyText(new DisassemblySettings()).back().addr);
					std::string error;
					DataBuffer Buf;
					if (g_bv->GetDefaultArchitecture()->Assemble(fmt::format("jmp {} {}", UtilsGetJmpType(BB->GetDisassemblyText(new DisassemblySettings()).back().addr, Start), Start), BB->GetDisassemblyText(new DisassemblySettings()).back().addr, Buf, error)) {
						LogInfo("[Solve_Jmp_ConstantPtr] InstrtionSize %d, OriginJmpInstrtionSize %d %s", Buf.GetLength(), OriginJmpInstrtionSize, hex(Buf).c_str());
						// !不要Patch Jumptable
						if (Buf.GetLength() == 2 && OriginJmpInstrtionSize == 2) {
							g_bv->WriteBuffer(BB->GetDisassemblyText(new DisassemblySettings()).back().addr, Buf);
						}
					}
					else {
						LogError("[Solve_Jmp_ConstantPtr] Error 1 , {:#x}", BB->GetDisassemblyText(new DisassemblySettings()).back().addr);
					}
				}
			}
		}
		//break;
	}
}

// 利用自己写的数据流分析算法做优化
void Solve_Jmp_ConstantPtr2() {
	for (auto Func : g_bv->GetAnalysisFunctionList()) {
		LogInfo("[Solve_Jmp_ConstantPtr2] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		Func->SetAnalysisSkipOverride(NeverSkipFunctionAnalysis);
		auto MFunc = Func->GetMediumLevelIL();
		auto BBList = MFunc->GetBasicBlocks();
		for (const auto& BB : BBList) {
			auto EndIndex = BB->GetEnd();
			auto Terminator = MFunc->GetInstruction(EndIndex - 1);
			if (Terminator.operation == MLIL_JUMP) {
				LogInfo("[Solve_Jmp_ConstantPtr2] Get %llx", BB->GetDisassemblyText(new DisassemblySettings()).back().addr);
				auto Dest = get_possiable_value<int>(MFunc->GetSSAForm(), Terminator.GetSSAForm().GetDestExpr());
				if (Dest) {
					// 目的地确定
					LogInfo("[Solve_Jmp_ConstantPtr2] Get Constant %llx", 0);
				}
			}
		}
		break;
	}
}

// 这里其实也可以用AI搞一下,一个是准确率问题,一个是慢
//48 @ 100110f2  int32_t * ecx_3 = ebp_1 - 0x18
//49 @ 100110f5[ebp_1 - 0x18].d = 0x54
//50 @ 10011107  int32_t eax_7 = [ecx_3].d
//51 @ 10011109  int32_t edx_3 = 0xffffffce + eax_7
//52 @ 1001110b  void* ebx_3 = &data_10011101 + edx_3
//53 @ 1001110d[ebp_1 - 0x14].d = 0xc4
//❓  54 @ 10011114  jump(ebx_3)
void Solve_Call_ConstantPtr() {
	for (auto Func : g_bv->GetAnalysisFunctionList()) {
		LogInfo("[Solve_Call_ConstantPtr] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		Func->SetAnalysisSkipOverride(NeverSkipFunctionAnalysis);
		auto MFunc = Func->GetMediumLevelIL()->GetSSAForm();
		auto BBList = MFunc->GetBasicBlocks();
		for (const auto& BB : BBList) {
			auto EndIndex = BB->GetEnd();
			for (int i = 0; i < EndIndex; i++) {
				auto Inst = MFunc->GetInstruction(i);
				//LogDebug("[Solve_Call_ConstantPtr] Operation %s", magic_enum::enum_name(Inst.operation).data());
				if (Inst.operation == MLIL_CALL_UNTYPED_SSA && Inst.GetDestExpr().operation == MLIL_VAR_SSA) {
					LogInfo("[Solve_Call_ConstantPtr] Get %s", Inst.Dump());
					auto Dest = get_possiable_value<int>(MFunc->GetSSAForm(), Inst.GetDestExpr());
					if (Dest) {
						// 目的地确定
						LogInfo("[Solve_Call_ConstantPtr] Get Constant %llx", 0);
						continue;
					}
				}
			}
		}
		break;
	}
}