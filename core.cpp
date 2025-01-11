#include "core.h"
#include "utils.h"
#include <lowlevelilinstruction.h>


BinaryView* g_bv;

DataBuffer CleanBlock(uint64_t Start, uint64_t End, std::vector<uint64_t> NopAddressLists) {
	// Call指令移动位置需要修复
	auto _fix_call = [](uint64_t Addr,uint64_t NewAddr) -> DataBuffer{
		try {
			auto Instr = UtilsGetLowLevelIlAt(Addr);
			if (!Instr) {
				LogError("UtilsGetLowLevelIlAt fail , %llx", Addr);
				return{};
			}
			uint64_t tgt = Instr->GetRawOperandAsExpr(0).AsConstant().GetConstant();

			DataBuffer t;
			std::string error;
			if (!g_bv->GetDefaultArchitecture()->Assemble(fmt::format("call {:#x}", tgt), NewAddr, t, error)) {
				LogError("Assemble fail , %s", fmt::format("Addr {:x} NewAddr {:x} tgt {:x} error {}", Addr,NewAddr,tgt,error).c_str());
				return {};
			}
			else {
				LogDebug("_fix_call Addr %llx return %s", Addr,t.ToEscapedString().c_str());
				return t;
			}
		}
		catch (const std::exception& e) {
			LogError("_fix_call Exception Addr %llx", Addr,e.what());
			return {};
		}
	};
	
	auto _is_nop = [](std::vector<InstructionTextToken> tokens) {
		if (tokens.size() == 3 && tokens[1].text == "nop")
			return true;
		else
			return false;
	};

	// call sub_xxx
	auto _is_call = [](std::vector<InstructionTextToken> tokens) {
		if (tokens.size() >= 3 && tokens[1].text == "call" && tokens[3].text.find_first_of("sub_") != std::string::npos)
			return true;
		else
			return false;
	};

	DataBuffer BlockBytes;
	uint64_t CurAddr = Start;
	while (CurAddr < End) {
		size_t ilen = g_bv->GetInstructionLength(g_bv->GetDefaultArchitecture(), CurAddr);
		auto tokens = UtilsGetDisassemblyTextAt(CurAddr);
		// 地址不在列表内,且不是nop指令
		if (std::find(NopAddressLists.begin(), NopAddressLists.end(), CurAddr) == NopAddressLists.end() &&
			!_is_nop(tokens)) {
			// Call指令需要额外处理
			if (_is_call(tokens)) {
				auto data = _fix_call(CurAddr, Start + BlockBytes.GetLength());
				if (data.GetLength()) {
					BlockBytes.Append(data);
				}
			}
			else {
				BlockBytes.Append(g_bv->ReadBuffer(CurAddr, ilen));
			}
		}
		// 移动到下一条指令
		CurAddr += ilen;
	}
	return BlockBytes;
}

CFGLink::CFGLink(BasicBlock* Cur_BasicBlock, BasicBlock* True_BasicBlock, BasicBlock* False_BasicBlock,std::string JccType)
{
	this->Cur_BasicBlock = Cur_BasicBlock;
	this->True_BasicBlock = True_BasicBlock;
	this->False_BasicBlock = False_BasicBlock;
	this->jcc_type = JccType;
}

DataBuffer CFGLink::GenAsm(uint64_t BaseAddress) {
	DataBuffer Result;
	if (Is_Uncond()) {
		uint64_t DestAddress = True_BasicBlock->GetStart();
		LogDebug(fmt::format("Patching from {:x} to {:x}", BaseAddress, DestAddress).c_str());
		std::string errors;
		if (!g_bv->GetDefaultArchitecture()->Assemble(fmt::format("jmp {} {:#x}", UtilsGetJmpType(BaseAddress,DestAddress),DestAddress ), BaseAddress, Result, errors)) {
			LogError(("Assemble fail "+ errors).c_str());
			return {};
		}
		else {
			return Result;
		}
	}
	else {
		uint64_t True_Dest = True_BasicBlock->GetStart();
		uint64_t False_Dest = False_BasicBlock->GetStart();
		LogDebug(fmt::format("Patching from {:x} to T: {:x} F: {:x}", BaseAddress, True_Dest, False_Dest).c_str());
		//g_bv->GetDefaultArchitecture()->Assemble(fmt::format("{} {} {:#x}", this->jcc_type,GetJmpType(BaseAddress, DestAddress), DestAddress), BaseAddress, Result, errors);
		return Result;
	}
}
