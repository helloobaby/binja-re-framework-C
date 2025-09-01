//
// 1.���������DLL·�� %appdata%/Binary Ninja/plugins/
// 2.�õ���ʲô�汾��BinaryNinja��Ҫ�л���SDK��Ӧ�İ汾,��Ȼ���е�ʱ��ᱨ�汾��ƥ��
//

#include "examples/examples.h"

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
		// DllMain InitSDK UninitSDK
		EasyRegisterWrapper(Solve_All, "Solve_All", {0x10091CC0,0x10092700,0x100930A0 });



		return true;
	}

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
}
