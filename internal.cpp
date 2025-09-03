#include "stdafx.h"

namespace internal {
	void Init() {
		PluginCommand::Register("[DEBUG] Print DisassemblyText Token Details For Address", "", [](BinaryView* bv) {
			g_bv = bv;

			uint64_t Result;
			bv->GetAddressInput(Result, "Input DisassemblyText Address", "Info");
			auto tokens = UtilsGetDisassemblyTextAt(Result);
			for (int i = 0; i < tokens.size(); i++) {
				LogInfo("tokens[%d] -> %s", i, tokens[i].text.c_str());
			}
			}
		);

		PluginCommand::Register("[DEBUG] Print LowLevel IL Details For Address", "", [](BinaryView* bv) {
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
					if (LLIL_Instr)
						UtilsDumpLowlevelIl(LLIL_Instr.value(), 0);
					else {
						LogError("LLILFunction->GetInstruction(%d) fail", i);
					}
				}
			}
			catch (const std::exception& e) {
				LogError("Exception %s", e.what());
				UtilsShowTraceStack(nullptr);
			}});

			PluginCommand::Register("[DEBUG] CFGLink Test", "", [](BinaryView* bv) {
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
					CFGLink cfg2(BasicBlock.GetPtr(), True_BB->target.GetPtr(), False_BB->target.GetPtr());


				}
				catch (const std::exception& e) {
					LogError("Exception %s", e.what());
					UtilsShowTraceStack(nullptr);
				}
				});

	}
}