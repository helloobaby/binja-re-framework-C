#include "utils.h"
#include <lowlevelilinstruction.h>
#include <optional>
#include <iomanip>
#include <dbghelp.h>
#include <stdio.h>
#include "include/magic_enum/magic_enum.hpp"
#pragma comment(lib,"DbgHelp.Lib")

uint64_t UtilsGetAddressInput() {
	uint64_t Result;
	g_bv->GetAddressInput(Result, "Input Address", "Info");
	return Result;
}

std::optional<LowLevelILInstruction> UtilsGetLowLevelIlAt(uint64_t Addr) {
	auto Functions = g_bv->GetAnalysisFunctionsContainingAddress(Addr);
	if (!Functions.size())
		return std::nullopt;
	size_t idx = Functions[0]->GetLowLevelILForInstruction(g_bv->GetDefaultArchitecture(), Addr);
	auto Instr = Functions[0]->GetLowLevelIL()->GetInstruction(idx);
	return Instr;
}

std::vector<InstructionTextToken> UtilsGetDisassemblyTextAt(uint64_t Addr) {
	auto BasicBlock = g_bv->GetBasicBlocksForAddress(Addr)[0];
	auto t = BasicBlock->GetDisassemblyText(new DisassemblySettings());
	auto find = std::find_if(t.begin(), t.end(), [&](DisassemblyTextLine TextLine) {
		if (TextLine.addr == Addr)
			return true; else
			return false; });
	if (find != t.end()) {
		return find->tokens;
	}
	else {
		return {};
	}
}

std::string hex(DataBuffer Buffer) {
	std::ostringstream oss;
	for (int i = 0; i < Buffer.GetLength(); i++) {
		oss << "0x" << std::setw(2)
			<< std::setfill('0')
			<< std::hex
			<< static_cast<int>(Buffer[i]) << " ";
	}
	return oss.str();
}

void UtilsShowTraceStack(char* szBriefInfo /*= NULL*/)
{
#define STACK_INFO_LEN  1024
#define MAXSHORT 12
	void* pStack[MAXSHORT];
	static char szStackInfo[STACK_INFO_LEN * MAXSHORT];
	static char szFrameInfo[STACK_INFO_LEN];

	HANDLE process = GetCurrentProcess();
	SymInitialize(process, NULL, TRUE);
	WORD frames = CaptureStackBackTrace(0, MAXSHORT, pStack, NULL);
	strcpy(szStackInfo, szBriefInfo == NULL ? "Stack Traceback:\n" : szBriefInfo);

	for (WORD i = 0; i < frames; ++i) {
		DWORD64 address = (DWORD64)(pStack[i]);

		DWORD64 displacementSym = 0;
		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;

		DWORD displacementLine = 0;
		IMAGEHLP_LINE64 line;
		line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

		if (SymFromAddr(process, address, &displacementSym, pSymbol) && SymGetLineFromAddr64(process, address, &displacementLine, &line))
		{
			snprintf(szFrameInfo, sizeof(szFrameInfo), "\t%s() at %s:%d(0x%x)\n", pSymbol->Name, line.FileName, line.LineNumber, pSymbol->Address);
		}
		else
		{
			snprintf(szFrameInfo, sizeof(szFrameInfo), "\tUnknowAddress : LastError %d\n", GetLastError());
		}
		strcat(szStackInfo, szFrameInfo);
	}

	LogInfo("%s", szStackInfo);
}

std::string UtilsGetJmpType(uint64_t BaseAddress, uint64_t DestAddress) {
	int64_t offset = static_cast<int64_t>(DestAddress - BaseAddress); // 

	if (offset >= -128 && offset <= 127) {
		return "short"; // ¶ÌÌø×ª
	}
	else {
		return "near"; // ³¤Ìø×ª
	}
}

bool UtilsDumpLowlevelIl(const LowLevelILInstruction& instr) {
	LogInfo("instr(%d) Operation %s",instr.instructionIndex ,magic_enum::enum_name(instr.operation).data());
	if (instr.operation == LLIL_REG) {

		LogInfo("\t%s ", magic_enum::enum_name(instr.operation).data());
		auto Reg = instr.GetSourceRegister()
		return true;
	}

	if (instr.operation == LLIL_CONST || instr.operation  == LLIL_CONST_PTR || instr.operation == LLIL_EXTERN_PTR) {
		LogInfo("\t%s %llx", magic_enum::enum_name(instr.operation).data(),instr.GetConstant());
		return true;
	}

	//instr.VisitExprs(UtilsDumpLowlevelIl);
	return true;
}