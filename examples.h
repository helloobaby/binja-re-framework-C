#pragma once
#include "core.h"
#include "binaryninjaapi.h"
#include <lowlevelilinstruction.h>
#include "utils.h"
#include "include/magic_enum/magic_enum.hpp"
#include <exception>
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
					if (NextInstructionTokens.size() == 4 && NextInstructionTokens[1].text == "pop") {
						// 利用模式匹配找到这种地址 
						LogInfo("[Solve_CallPop] %llx", DisTokenList[i].addr);
						std::string reg = NextInstructionTokens[3].text;
						// Nop这两条指令
						g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), DisTokenList[i].addr);
						g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), DisTokenList[i+1].addr);

						std::string error;
						DataBuffer Buf;
						if (g_bv->GetDefaultArchitecture()->Assemble(fmt::format("mov {},{:#x}", reg, DisTokenList[i + 1].addr), 0, Buf, error)) {
							LogInfo("%s", hex(Buf).c_str());
							g_bv->WriteBuffer(DisTokenList[i].addr, Buf);
						}
						else {
							LogError("[Solve_CallPop] Error 1 , {:#x}", DisTokenList[i].addr);
						}
					}
				}
			}
		}
	}
}
