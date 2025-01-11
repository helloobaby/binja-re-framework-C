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

#ifndef TESTPLUGIN_LIBRARY_H
#define TESTPLUGIN_LIBRARY_H

#include "binaryninjaapi.h"

#endif //TESTPLUGIN_LIBRARY_H

using namespace BinaryNinja;
extern BinaryView* g_bv;


// �������BasicBlock,NopAddressLists��������Ҫ��ָ���ַ,����ʣ���ָ���ֽ�DataBuffer
// 
DataBuffer CleanBlock(uint64_t Start, uint64_t End, std::vector<uint64_t> NopAddressLists);

class CFGLink {
public:
	CFGLink(BasicBlock* Cur_BasicBlock ,BasicBlock* True_BasicBlock, BasicBlock* False_BasicBlock = nullptr , std::string JccType = "");
	bool Is_Uncond() { return False_BasicBlock == nullptr; }
	bool Is_Cond() { return !Is_Uncond(); }
	DataBuffer GenAsm(uint64_t BaseAddress);
private:
	BasicBlock* Cur_BasicBlock;
	BasicBlock* True_BasicBlock;
	BasicBlock* False_BasicBlock;
	std::string jcc_type;
};

