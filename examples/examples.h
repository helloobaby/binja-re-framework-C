#pragma once
#include "core.h"
#include "binaryninjaapi.h"
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include "utils.h"
#include "include/magic_enum/magic_enum.hpp"
#include <exception>
#include <dbghelp.h>
#include <vector>
using namespace BinaryNinja;
extern BinaryView* g_bv;

//10001096  e800000000         call    $ + 5  {data_1000109b}
//1000109b  5f                 pop     edi						-> mov edi,0x1000109b
void Solve_CallPop(std::vector<uint64_t> DebugFunctionList) {
	std::vector<Ref<Function>> DefaultFunctionList;
	if (DebugFunctionList.size()) {
		for (auto Addr : DebugFunctionList) {
			auto t = g_bv->GetAnalysisFunctionsContainingAddress(Addr);
			DefaultFunctionList.insert(DefaultFunctionList.end(),t.cbegin(), t.cend());
		}
	}
	else {
		DefaultFunctionList = g_bv->GetAnalysisFunctionList();
	}
	for (auto& Func : DefaultFunctionList) {
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
					}
				}
			}
		}
		//break;
	}
}

//1000255d  push    edi {var_8}
//1000255e  retn    反编译看到ret直接认为函数到末尾停止分析了,需要Patch成为Jmp
void Solve_Push_Ret(std::vector<uint64_t> DebugFunctionList) {
	std::vector<Ref<Function>> DefaultFunctionList;
	if (DebugFunctionList.size()) {
		for (auto Addr : DebugFunctionList) {
			auto t = g_bv->GetAnalysisFunctionsContainingAddress(Addr);
			DefaultFunctionList.insert(DefaultFunctionList.end(), t.cbegin(), t.cend());
		}
	}
	else {
		DefaultFunctionList = g_bv->GetAnalysisFunctionList();
	}
	for (auto Func : DefaultFunctionList) {
		LogInfo("[Solve_Push_Ret] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		auto BBList = Func->GetBasicBlocks();
		for (const auto& BB : BBList) {
			const auto& DisTokenList = BB->GetDisassemblyText(new DisassemblySettings());
			for (int i = 0; i < DisTokenList.size(); i++) {
				if (i == (DisTokenList.size() - 1))
					break;
				if (DisTokenList.size() < 2)
					break;
				uint64_t TerminatorAddr = DisTokenList.back().addr;
				DataBuffer Buf = g_bv->ReadBuffer(TerminatorAddr, 1);
				// ret
				if (Buf[0] == 0xC3 ) {
					DataBuffer Opcode = g_bv->ReadBuffer(TerminatorAddr - 1, 1);
					// push eax -> push edi
					if (Opcode[0] >= 0x50 && Opcode[0] <= 0x57) {
						LogInfo("[Solve_Push_Ret] Get %llx", TerminatorAddr - 1);
						auto reg = DisTokenList[DisTokenList.size() - 2].tokens[3].text;
						std::string error;
						DataBuffer Buf;
						g_bv->GetDefaultArchitecture()->Assemble(fmt::format("jmp {}", reg), 0, Buf, error);
						if (Buf.GetLength() == 2) {
							g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), TerminatorAddr);
							g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), TerminatorAddr - 1);
							g_bv->WriteBuffer(TerminatorAddr, Buf);
							// 迭代下一个BasicBlock
							break;
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
		if (ssa_def.operation != MLIL_SET_VAR_SSA && ssa_def.operation != MLIL_SET_VAR_ALIASED) {
			LogDebug("[%s] ssa_def.operation %s invalid ", __FUNCTION__, magic_enum::enum_name(ssa_def.operation).data());
			return std::nullopt;
		}
		auto source = ssa_def.GetSourceExpr();
		auto source_operation = source.operation;

		LogDebug("[%s] ssa_def %s operation %s , source_operation %s", __FUNCTION__, ssa_def.Dump(), magic_enum::enum_name(ssa_def.operation).data(), magic_enum::enum_name(source_operation).data());

		// 从堆栈中读取
		//16 @ 1004e523[arg2#0 - 0x18].d = 0xc0 @ mem#1->mem#3
		//17 @ 1004e53a  eax_2#3 = [arg3#0].d @ mem#3              -> var
		if (source_operation == MLIL_LOAD_SSA) {
			auto operand = source.GetRawOperandAsExpr(0);
			LogDebug("[get_possiable_value] Get LOAD_SSA Operation %s", magic_enum::enum_name(operand.operation).data());
			if (operand.operation == MLIL_VAR_SSA/* || operand.operation == MLIL_VAR_PHI*/) {
				size_t search_end = ssa_def.GetSSAInstructionIndex();
				auto cur_bb = Func->GetBasicBlockForInstruction(search_end);
				if (cur_bb) {
					// 有两种情况,一种是MLIL会优化到变量,一种是无法优化
					//  286 @ 10001537  var_1c @ mem#26 -> mem#27 = 0xf
					for (size_t i = cur_bb->GetStart(); i < search_end; i++) {
						auto instr = Func->GetInstruction(i);
						if (instr.operation == MLIL_SET_VAR_ALIASED) {
							auto dest = instr.GetDestSSAVariable();
							auto name = Func->GetFunction()->GetVariableName(dest.var);
							if (std::string(name).find("var_1c") != std::string::npos) {
								auto src = instr.GetSourceExpr();
								if (src.operation == MLIL_CONST || src.operation == MLIL_CONST_PTR) {
									auto guess_value = src.GetConstant();
									LogInfo("guess constant method1 %llx", guess_value);
									if (guess_value < 0xff && guess_value > 0)
										return guess_value;
								}
							}
						}
					}

					//  10001537  mov     dword [ebp-0x18 {var_1c}], 0xf  -> 
					for (size_t i = cur_bb->GetStart(); i < search_end; i++) {
						auto instr = Func->GetInstruction(i);
						if (instr.operation == MLIL_STORE_SSA) {
							auto src = instr.GetSourceExpr();
							if (src.operation == MLIL_CONST || src.operation == MLIL_CONST_PTR) {
								auto guess_value = src.GetConstant();
								LogInfo("guess constant method2 %llx", guess_value);
								if (guess_value < 0xff && guess_value > 0)
									return guess_value;
							}
						}
					}
				}
				else {
					LogDebug("CantFind cur_bb");
				}
			}
			else
				return std::nullopt;
		}

		if (source_operation != MLIL_ADD && source_operation != MLIL_SUB && source_operation != MLIL_XOR && source_operation != MLIL_MUL && source_operation != MLIL_AND
			&& source_operation != MLIL_VAR_SSA && source_operation != MLIL_VAR_ALIASED && source_operation != MLIL_CONST && source_operation != MLIL_CONST_PTR) {
			LogDebug("[%s] source_operation %s invalid", __FUNCTION__, magic_enum::enum_name(source_operation).data());
			return std::nullopt;
		}
		auto op_count = source.GetOperands().size();
		LogDebug("[%s] op_count %d", __FUNCTION__, op_count);
		if (op_count == 1) {
			return get_possiable_value<T>(Func,source);
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
		break;
	}
}

// 利用自己写的数据流分析算法做优化
void Solve_Jmp_ConstantPtr_myalgo(std::vector<uint64_t> DebugFunctionList) {
	std::vector<Ref<Function>> DefaultFunctionList;
	if (DebugFunctionList.size()) {
		for (auto Addr : DebugFunctionList) {
			auto t = g_bv->GetAnalysisFunctionsContainingAddress(Addr);
			DefaultFunctionList.insert(DefaultFunctionList.end(), t.cbegin(), t.cend());
		}
	}
	else {
		DefaultFunctionList = g_bv->GetAnalysisFunctionList();
	}
	for (auto Func : DefaultFunctionList) {
		LogInfo("[Solve_Jmp_ConstantPtr_myalgo] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		Func->SetAnalysisSkipOverride(NeverSkipFunctionAnalysis);
		auto MFunc = Func->GetMediumLevelIL();
		if (!MFunc)
			continue;
		auto BBList = MFunc->GetBasicBlocks();
		for (const auto& BB : BBList) {
			auto EndIndex = BB->GetEnd();
			auto Terminator = MFunc->GetInstruction(EndIndex - 1);
			if (Terminator.operation == MLIL_JUMP || Terminator.operation == MLIL_JUMP_TO) {
				LogInfo("[Solve_Jmp_ConstantPtr_myalgo] Get %llx", BB->GetDisassemblyText(new DisassemblySettings()).back().addr);
				auto Dest = get_possiable_value<int>(MFunc->GetSSAForm(), Terminator.GetSSAForm().GetDestExpr());
				if (Dest) {
					// 目的地确定
					LogInfo("[Solve_Jmp_ConstantPtr_myalgo] Get Constant %llx", *Dest);
					DataBuffer Buf;
					std::string error;
					if (g_bv->GetDefaultArchitecture()->Assemble(fmt::format("jmp {} {}", UtilsGetJmpType(Terminator.address, *Dest), *Dest), Terminator.address, Buf, error)) {
						if (Buf.GetLength() == 2) {
							g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), Terminator.address);
							g_bv->WriteBuffer(Terminator.address, Buf);
						}
					}
					// 迭代下一个BasicBlock
					continue;
				}
			}
		}
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
void Solve_Call_ConstantPtr(std::vector<uint64_t> DebugFunctionList) {
	std::vector<Ref<Function>> DefaultFunctionList;
	if (DebugFunctionList.size()) {
		for (auto Addr : DebugFunctionList) {
			auto t = g_bv->GetAnalysisFunctionsContainingAddress(Addr);
			DefaultFunctionList.insert(DefaultFunctionList.end(), t.cbegin(), t.cend());
		}
	}
	else {
		DefaultFunctionList = g_bv->GetAnalysisFunctionList();
	}
	for (auto Func : DefaultFunctionList) {
		LogInfo("[Solve_Call_ConstantPtr] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		Func->SetAnalysisSkipOverride(NeverSkipFunctionAnalysis);
		auto MFunc = Func->GetMediumLevelIL();
		if (!MFunc)
			continue;
		MFunc = MFunc->GetSSAForm();
		auto BBList = MFunc->GetBasicBlocks();
		for (const auto& BB : BBList) {
			//auto EndIndex = BB->GetEnd();
			for (int i = BB->GetStart(); i < BB->GetEnd(); i++) {
				auto Inst = MFunc->GetInstruction(i);
				LogDebug("[Solve_Call_ConstantPtr] %d Operation %s",i, magic_enum::enum_name(Inst.operation).data());
				if ((Inst.operation == MLIL_CALL_UNTYPED_SSA || Inst.operation == MLIL_CALL_SSA)/* && Inst.GetDestExpr().operation == MLIL_VAR_SSA*/) {
					LogDebug("[Solve_Call_ConstantPtr] Get %s", Inst.Dump());
					auto Dest = get_possiable_value<int>(MFunc->GetSSAForm(), Inst.GetDestExpr());
					if (Dest) {
						// 目的地确定
						LogInfo("[Solve_Call_ConstantPtr] Get Constant %llx", *Dest);
						DataBuffer Buf;
						Buf = g_bv->ReadBuffer(*Dest, 1);
						// pop eax -> pop edi
						// 只能通过opcode判断,因为binaryninja还没分析这个目的地,无法用一些汇编tokens啥的判断
						if (Buf[0] >=0x58 && Buf[0] <= 0x5f) {
							LogInfo("Can Patch to Jmp");
							std::string error;
							if (g_bv->GetDefaultArchitecture()->Assemble(fmt::format("jmp {} {}", UtilsGetJmpType(Inst.address, *Dest), *Dest), Inst.address, Buf, error)) {
								if (Buf.GetLength() == 2) {
									g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), Inst.address);
									g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), *Dest);
									g_bv->WriteBuffer(Inst.address, Buf);
								}
							}
						}
						break;
					}
				}
			}
		}
	}
}
//.text:10001E36                 jnb     short near ptr loc_10001E45 + 4
//.text:10001E38                 jb      short near ptr loc_10001E45 + 4
void Solve_Unreachable_Jcc(std::vector<uint64_t> DebugFunctionList) {
	std::vector<Ref<Function>> DefaultFunctionList;
	if (DebugFunctionList.size()) {
		for (auto Addr : DebugFunctionList) {
			auto t = g_bv->GetAnalysisFunctionsContainingAddress(Addr);
			DefaultFunctionList.insert(DefaultFunctionList.end(), t.cbegin(), t.cend());
		}
	}
	else {
		DefaultFunctionList = g_bv->GetAnalysisFunctionList();
	}
	for (auto& Func : DefaultFunctionList) {
		LogInfo("[Solve_Unreachable_Jcc] Solve %s", Func->GetSymbol()->GetFullName().c_str());
		Func->SetAnalysisSkipOverride(NeverSkipFunctionAnalysis);
		auto BBList = Func->GetBasicBlocks();
		for (const auto& BB : BBList) {
			auto OutgoingEdges = BB->GetOutgoingEdges();
			if (OutgoingEdges.size() != 2) {
				continue;
			}
			auto False_BB = std::find_if(OutgoingEdges.begin(), OutgoingEdges.end(), [](BasicBlockEdge e) {
				if (e.type == FalseBranch)
					return true;
				else
					return false;
				});
			auto True_BB_Cur = std::find_if(OutgoingEdges.begin(), OutgoingEdges.end(), [](BasicBlockEdge e) {
				if (e.type == TrueBranch)
					return true;
				else
					return false;
				});
			if (False_BB == OutgoingEdges.end() || True_BB_Cur == OutgoingEdges.end()) {
				LogError("[Solve_Unreachable_Jcc] Error 1 %llx", BB->GetStart());
				continue;
			}
			auto OutgoingEdges_Next = False_BB->target->GetOutgoingEdges();
			if (OutgoingEdges_Next.size() != 2) {
				continue;
			}

			auto True_BB = std::find_if(OutgoingEdges_Next.begin(), OutgoingEdges_Next.end(), [](BasicBlockEdge e) {
				if (e.type == TrueBranch)
					return true;
				else
					return false;
				});
			if (True_BB == OutgoingEdges_Next.end()) {
				LogError("[Solve_Unreachable_Jcc] Error 2 %llx", BB->GetStart());
				continue;
			}
			if (True_BB->target->GetStart() == True_BB_Cur->target->GetStart()) {
				LogInfo("[Solve_Unreachable_Jcc] Get %llx", BB->GetStart());
				g_bv->AlwaysBranch(g_bv->GetDefaultArchitecture(), BB->GetDisassemblyText(new DisassemblySettings()).back().addr);
			}
		}
	}
}

// C++ Plugin的Patch和Python的不太一样
// C++插件Patch应该是等我们的代码运行完之后,BinaryNinja才开始重新分析,所以不需要最后一起Patch
// Python的应该是边Patch边分析,所以有时候会报错这样
void Solve_All(std::vector<uint64_t> DebugFunctionList) {
	/*for (int i = 0; i < 10; i++) {
		Solve_CallPop(DebugFunctionList);
		Solve_Push_Ret(DebugFunctionList);
		Solve_Unreachable_Jcc(DebugFunctionList);
		Solve_Call_ConstantPtr(DebugFunctionList);
		Solve_Jmp_ConstantPtr_myalgo(DebugFunctionList);
		g_bv->UpdateAnalysisAndWait();  // 这样好像是没用的,因为你代码不跑完他没机会重新分析,调也没用
	}*/
	
	// C++没有Python那种current_address,只能这样代替下方便测试单个函数
	//uint64_t addr = UtilsGetAddressInput();
	//DebugFunctionList.push_back(addr);

	Solve_CallPop(DebugFunctionList);
	Solve_Push_Ret(DebugFunctionList);
	Solve_Unreachable_Jcc(DebugFunctionList);
	Solve_Call_ConstantPtr(DebugFunctionList);
	Solve_Jmp_ConstantPtr_myalgo(DebugFunctionList);
}