// MIT License
// 
// Copyright (c) 2015-2024 Vector 35 Inc
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "examples.h"

using namespace BinaryNinja;

extern "C"
{
	extern "C" 
	{ 
		// [Default] This plugin was built for a newer version of Binary Ninja (XX). 
		// Please update Binary Ninja or rebuild the plugin with the matching API version (XX).
		BINARYNINJAPLUGIN uint32_t CorePluginABIVersion() {  
			// git pull origin dev
			return BN_CURRENT_CORE_ABI_VERSION;
		} 
	}

	BINARYNINJAPLUGIN bool CorePluginInit() 
	{
		//EasyRegisterWrapper(Solve_CallPop, "Solve_CallPop", {  });
		//EasyRegisterWrapper(Solve_Push_Ret, "Solve_Push_Ret", {  });
		//EasyRegisterWrapper(Solve_Call_ConstantPtr, "Solve_Call_ConstantPtr", {  });
		//EasyRegisterWrapper(Solve_Jmp_ConstantPtr_myalgo, "Solve_Jmp_ConstantPtr_myalgo", {  });
		//EasyRegisterWrapper(Solve_Unreachable_Jcc, "Solve_Unreachable_Jcc", {  });
		EasyRegisterWrapper(Solve_All, "Solve_All", { });

		PluginCommand::Register("CFGLink Test", "", [](BinaryView* bv) {
			g_bv = bv;
			try {
				uint64_t Result;
				bv->GetAddressInput(Result, "Input Address", "Info");
				auto BasicBlocks = bv->GetBasicBlocksForAddress(Result);
				LogInfo("GetBasicBlocksForAddress return %d", BasicBlocks.size());
				if (BasicBlocks.empty())
					return;
				auto BasicBlock = BasicBlocks[0];
				auto OutgoingEdges = BasicBlock->GetOutgoingEdges();
				if (OutgoingEdges.size() != 2) {
					LogError("OutgoingEdges != 2 , Input new address");
					return;
				}

				auto True_BB = std::find_if(OutgoingEdges.begin(), OutgoingEdges.end(), [](BasicBlockEdge e) {
					if (e.type == TrueBranch)
						return true;
					else
						return false;
					});

				auto False_BB = std::find_if(OutgoingEdges.begin(), OutgoingEdges.end(), [](BasicBlockEdge e) {
					if (e.type == FalseBranch)
						return true;
					else
						return false;
					});

				CFGLink cfg(BasicBlock.GetPtr(), True_BB->target.GetPtr());
				uint64_t TerminatorAddr = BasicBlock->GetDisassemblyText(new DisassemblySettings()).back().addr;
				DataBuffer Buffer = cfg.GenAsm(TerminatorAddr);
				LogInfo("CFGLink %s", hex(Buffer).c_str());

				// 直接JMP到True基本块
				//g_bv->ConvertToNop(g_bv->GetDefaultArchitecture(), TerminatorAddr);
				//if (!g_bv->WriteBuffer(TerminatorAddr, Buffer)) {
					//LogError("WriteBuffer fail %llx", TerminatorAddr);
				//}

				// 将True基本块和False基本块反一下
				CFGLink cfg2(BasicBlock.GetPtr(), True_BB->target.GetPtr(),False_BB->target.GetPtr());
				

			}
			catch (const std::exception& e) {
				LogError("Exception %s", e.what());
				UtilsShowTraceStack(nullptr);
			}
			});

		PluginCommand::Register("Print LowLevel IL For Address (DEBUG)", "", [](BinaryView* bv) {
			try {
				g_bv = bv;

				uint64_t TestAddress = UtilsGetAddressInput();
				auto Functions = bv->GetAnalysisFunctionsContainingAddress(TestAddress);
				if (Functions.size() != 1) {
					LogWarn("Functions size is %d", Functions.size());
					return;
				}
				auto LLILFunction = Functions[0]->GetLowLevelIL();
				auto LLIL_Instr = UtilsGetLowLevelIlAt(TestAddress);
				if (!LLIL_Instr) {
					LogError("UtilsGetLowLevelIlAt fail  %llx", TestAddress);
					return;
				}

				// https://github.com/Vector35/binaryninja-api/blob/49bafa9cd9c0301235e806e0f868cf16cdaac405/examples/llil_parser/src/llil_parser.cpp
				for (auto LLIL_BB : LLILFunction->GetBasicBlocks()) {
					LogInfo("LLIL_BB Start %d End %d Length %d", LLIL_BB->GetStart(), LLIL_BB->GetEnd(), LLIL_BB->GetLength());
					
				}

				// 打印每条Lowlevel IL指令
				for (auto i = 0; i < LLILFunction->GetInstructionCount(); i++) {
					LLIL_Instr = LLILFunction->GetInstruction(i);
					if(LLIL_Instr)
						UtilsDumpLowlevelIl(LLIL_Instr.value(),0);
					else {
						LogError("LLILFunction->GetInstruction(%d) fail",i);
					}
				}
			}
			catch (const std::exception& e) {
				LogError("Exception %s", e.what());
				UtilsShowTraceStack(nullptr);
			}});
		PluginCommand::Register("Print DisassemblyText Token For Address (DEBUG)", "", [](BinaryView* bv) {
			g_bv = bv;

			uint64_t Result;
			bv->GetAddressInput(Result, "Input DisassemblyText Address", "Info");
			auto tokens = UtilsGetDisassemblyTextAt(Result);
			for (int i = 0; i < tokens.size(); i++) {
				LogInfo("tokens[%d] -> %s", i, tokens[i].text.c_str());
			}
			}
		);
		return true;
	}

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
}
